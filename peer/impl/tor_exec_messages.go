package impl

import (
	"fmt"

	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) execTorRelayMessage(msg types.Message, pkt transport.Packet) error {
	var err error
	torRelayMessage, ok := msg.(*types.TorRelayMessage)
	if !ok {
		err = fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(err).Msgf("[%s]: execTorRelayMessage failed, the message is not of the expected type. the message: %v", n.addr, torRelayMessage)
		return err
	}
	nextRoutingEntry, err := n.torManager.GetNextHop(torRelayMessage.CircuitID)
	if err != nil {
		// circuit does not exist
		return err
	}
	if nextRoutingEntry.CircuitID != torRelayMessage.CircuitID {
		// message is not for us if we have to change circuitID
		torRelayMessage.CircuitID = nextRoutingEntry.CircuitID
		torRelayMessage.LastHop = n.addr
		n.SendTLSMessage(nextRoutingEntry.NextHop, torRelayMessage)
		return nil
	}
	return nil
}

func (n *node) execTorControlMessage(msg types.Message, pkt transport.Packet) error {
	var err error
	torControlMessage, ok := msg.(*types.TorControlMessage)
	if !ok {
		err = fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(err).Msgf("[%s]: execTorControlMessage failed, the message is not of the expected type. the message: %v", n.addr, torControlMessage)
		return err
	}

	switch torControlMessage.Cmd {
	case types.Create:
		// Alice (1) -> Bob (2) -> Charlie
		// Bob's table: 1->(2, Charlie); 2->(1, Alice)
		// Alice (1) -> Bob
		// Bob's table: 1->(1, ALICE)
		// Bob knows the message is for him because he is not changing circuitID
		// Bob knows to respond to Alice
		// ....
		// Alice (1) -> Bob [EXTEND]
		// Bob's table becomes: (1->2, Charlie)
		// Bob now knows to forward the message
		// Charlie's table: (2, Bob)
		// He knows he is the destination
		n.torManager.torRoutingTable.Set(torControlMessage.CircuitID, peer.TorRoutingEntry{CircuitID: torControlMessage.CircuitID, NextHop: torControlMessage.LastHop})
		torClientHelloMessageBytes, err := n.tlsManager.DecryptPublicTor(torControlMessage.Data)
		if err != nil {
			logr.Logger.Err(err).Msgf("[%s]: execTorControlMessage failed, the message is not of the expected type. the message: %v", n.addr, torControlMessage)
			return err
		}
		transportMessage := transport.Message{
			Payload: torClientHelloMessageBytes,
			Type:    types.TorClientHello{}.Name(),
		}
		var newMessage types.TorClientHello
		n.conf.MessageRegistry.UnmarshalMessage(&transportMessage, &newMessage)
		logr.Logger.Info().Msgf("[%s]: execTorControlMessage %s", n.addr, torControlMessage.LastHop)
		n.execTorClientHelloMessage(newMessage, torControlMessage.LastHop, torControlMessage.CircuitID)

	case types.Created:
		transportMessage := transport.Message{
			Payload: torControlMessage.Data,
			Type:    types.TorServerHello{}.Name(),
		}
		var newMessage types.TorServerHello
		n.conf.MessageRegistry.UnmarshalMessage(&transportMessage, &newMessage)
		n.execTorServerHello(newMessage, torControlMessage.CircuitID)
	}

	return nil
}

func (n *node) execTorClientHelloMessage(msg types.Message, lastHop, circuitID string) error {
	var err error
	logr.Logger.Info().Msgf("[%s]: execTorClientHelloMessage %s", n.addr, lastHop)
	torClientHelloMessage, ok := msg.(types.TorClientHello)
	if !ok {
		err = fmt.Errorf("execTorClientHelloMessage failed, the message is not of the expected type. the message: %v", torClientHelloMessage)
		logr.Logger.Err(err).Msgf("[%s]: execTorClientHelloMessage failed, the message is not of the expected type. the message: %v", n.addr, torClientHelloMessage)
		return err
	}
	dhManager, err := n.DHfirstStepWithParams(torClientHelloMessage.PrimeDH, torClientHelloMessage.GroupDH)
	if err != nil {
		return err
	}
	n.tlsManager.SetDHManagerEntryTor(lastHop, circuitID, &dhManager)

	pub := dhManager.dhKey.Bytes()
	a := torClientHelloMessage.ClientPresecretDH
	ck, err := n.DHsecondStep(dhManager, a)
	if err != nil {
		return err
	}
	n.tlsManager.SetSymmKeyTor(circuitID, ck)

	sign, err := n.tlsManager.SignMessage(ck)
	if err != nil {
		return err
	}
	sm := types.TorServerHello{
		ServerPresecretDH: pub,
		Signature:         sign,
		Source:            n.addr,
	}
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(&sm)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error marshaling TLSServerHello to %s", n.addr, lastHop)
		return err
	}
	torControlMessage := types.TorControlMessage{
		LastHop:   n.addr,
		CircuitID: circuitID,
		Cmd:       types.Created,
		Data:      transportMessage.Payload,
	}

	return n.SendTLSMessage(lastHop, torControlMessage)

}

func (n *node) execTorServerHello(msg types.Message, circuitID string) error {
	var err error
	torServerHello, ok := msg.(types.TorServerHello)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: execTorServerHello failed", n.addr)
		return err
	}
	dhManager := n.tlsManager.GetDHManagerEntryTor(torServerHello.Source, circuitID)
	if dhManager == nil {
		logr.Logger.Err(err).Msgf("[%s]: execTorServerHello dhManager.Get failed!", n.addr)
		return fmt.Errorf("[%s]: execTorServerHello dhManager. Get failed", n.addr)
	}
	ck, err := n.DHsecondStep(*dhManager, torServerHello.ServerPresecretDH)
	if !n.tlsManager.VerifySignature(ck, torServerHello.Signature, torServerHello.Source) {
		logr.Logger.Err(err).Msgf("[%s]: execTorServerHello VerifySignature failed!", n.addr)
		return err
	}
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: execTorServerHello ComputeKey failed!", n.addr)
		return err
	}
	n.tlsManager.SetSymmKeyTor(circuitID, ck)
	logr.Logger.Info().Msgf("[%s]: execTorServerHello success!", n.addr)
	return nil
}
