package impl

import (
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) execTorRelayMessage(msg types.Message, pkt transport.Packet) error {
	var err error
	torRelayMessage, ok := msg.(*types.TorRelayMessage)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: execTorRelayMessage failed, the message is not of the expected type. the message: %v", n.addr, torRelayMessage)
		return err
	}
	nextRoutingEntry, err := n.torManager.GetNextHop(torRelayMessage.CircuitID)
	if err != nil {
		// circuit does not exist
		return err
	}
	if nextRoutingEntry.nextHop != n.addr {
		// message is not for us
		torRelayMessage.CircuitID = nextRoutingEntry.circuitID
		torRelayMessage.LastHop = n.addr
		n.SendTLSMessage(nextRoutingEntry.nextHop, torRelayMessage)
		return nil
	}
	return nil
}

func (n *node) execTorControlMessage(msg types.Message, pkt transport.Packet) error {
	var err error
	torControlMessage, ok := msg.(*types.TorControlMessage)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: execTorControlMessage failed, the message is not of the expected type. the message: %v", n.addr, torControlMessage)
		return err
	}
	// if torControlMessage.Cmd == types.Create {
	// 	n.torManager.torRoutingTable.Set(torControlMessage.CircuitID)
	// }
	return nil
}

func (n *node) execTorClientHelloMessage(msg types.Message, pkt transport.Packet) error {
	var err error
	torClientHelloMessage, ok := msg.(*types.TorClientHello)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: execTorClientHelloMessage failed, the message is not of the expected type. the message: %v", n.addr, torClientHelloMessage)
		return err
	}
	dhManager, err := n.DHfirstStepWithParams(torClientHelloMessage.PrimeDH, torClientHelloMessage.GroupDH)
	n.tlsManager.dhManager.Set(torClientHelloMessage.CircuitID, &dhManager)
	pub := dhManager.dhKey.Bytes()

	sm := types.TorServerHello{
		ServerPresecretDH: pub,
		CircuitID:         torClientHelloMessage.CircuitID,
	}
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(&sm)
	if err != nil {
		return err
	}

	return nil

}
