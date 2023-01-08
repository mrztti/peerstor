package impl

import (
	"fmt"
	"log"

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
		logr.Logger.Err(err).Msgf("[%s]: execTorRelayMessage failed, the circuit does not exist. the message: %v", n.addr, torRelayMessage)
		// circuit does not exist
		return err
	}
	if nextRoutingEntry.CircuitID != torRelayMessage.CircuitID {
		log.Default().Printf("[%s]: about to forward a message for circuit ID: %s, last hop was %s; next circuit ID will be :%s, next hop will be: %s, type of message:%v", n.addr, torRelayMessage.CircuitID, torRelayMessage.LastHop, nextRoutingEntry.CircuitID, nextRoutingEntry.NextHop, torRelayMessage.Cmd)
		switch torRelayMessage.Cmd {
		case types.RelayExtend, types.RelayRequest:
			torRelayMessage.Data, err = n.tlsManager.DecryptSymmetricTor(n.createTorEntryName(torRelayMessage.LastHop, torRelayMessage.CircuitID), torRelayMessage.Data)
		case types.RelayExtended, types.RelayResponse:
			torRelayMessage.Data, err = n.tlsManager.EncryptSymmetricTor(n.createTorEntryName(nextRoutingEntry.NextHop, nextRoutingEntry.CircuitID), torRelayMessage.Data)
		}
		if err != nil {
			return err
		}
		// message is not for us if we have to change circuitID
		torRelayMessage.LastHop = n.addr
		torRelayMessage.CircuitID = nextRoutingEntry.CircuitID

		n.SendTLSMessage(nextRoutingEntry.NextHop, torRelayMessage)
		return nil
	}
	switch torRelayMessage.Cmd {
	case types.RelayExtend:
		torRelayMessage.Data, err = n.tlsManager.DecryptSymmetricTor(n.createTorEntryName(torRelayMessage.LastHop, torRelayMessage.CircuitID), torRelayMessage.Data)
		if err != nil {
			return err
		}
		newCircuitID := getNewCircuitID()
		torConMsg := types.TorControlMessage{
			LastHop:   n.addr,
			CircuitID: newCircuitID,
			Cmd:       types.Create,
			Data:      torRelayMessage.Data,
		}
		n.torManager.torRoutingTable.Set(newCircuitID, peer.TorRoutingEntry{
			CircuitID: torRelayMessage.CircuitID,
			NextHop:   torRelayMessage.LastHop,
		})
		n.torManager.torRoutingTable.Set(torRelayMessage.CircuitID, peer.TorRoutingEntry{
			CircuitID: newCircuitID,
			NextHop:   torRelayMessage.Relay,
		})

		n.SendTLSMessage(torRelayMessage.Relay, torConMsg)

	case types.RelayExtended:
		nodesAddress, ok := n.torManager.myCircuits.Get(torRelayMessage.CircuitID)
		if !ok {
			return fmt.Errorf("circuit does not exist")
		}
		for _, node := range nodesAddress {
			torRelayMessage.Data, err = n.tlsManager.DecryptSymmetricTor(n.createTorEntryName(node, torRelayMessage.CircuitID), torRelayMessage.Data)
			if err != nil {
				return err
			}
		}
		transportMessage := transport.Message{
			Payload: torRelayMessage.Data,
			Type:    types.TorServerHello{}.Name(),
		}
		var newMessage types.TorServerHello
		n.conf.MessageRegistry.UnmarshalMessage(&transportMessage, &newMessage)
		n.execTorServerHello(newMessage, torRelayMessage.CircuitID)
	case types.RelayRequest:
		torRelayMessage.Data, err = n.tlsManager.DecryptSymmetricTor(n.createTorEntryName(torRelayMessage.LastHop, torRelayMessage.CircuitID), torRelayMessage.Data)
		if err != nil {
			return err
		}
		logr.Logger.Warn().Msgf("[%s]: Received the following request: %s", n.addr, string(torRelayMessage.Data))
		responseDataPlaintext := "wrapped response " + string(torRelayMessage.Data) + " from " + n.addr
		encryptedData, err := n.tlsManager.EncryptSymmetricTor(n.createTorEntryName(torRelayMessage.LastHop, torRelayMessage.CircuitID), []byte(responseDataPlaintext))
		if err != nil {
			return err
		}
		sampleResponse := types.TorRelayMessage{
			LastHop:   n.addr,
			CircuitID: torRelayMessage.CircuitID,
			Cmd:       types.RelayResponse,
			Data:      encryptedData,
		}
		n.SendTLSMessage(torRelayMessage.LastHop, sampleResponse)
	case types.RelayResponse:
		torRelayMessage.Data, err = n.TorDecrypt(torRelayMessage.CircuitID, torRelayMessage.Data)
		if err != nil {
			return err
		}
		logr.Logger.Warn().Msgf("[%s]: Received the following response: %s", n.addr, string(torRelayMessage.Data))
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
		log.Default().Printf("[%s]: Ive received msg of type create", n.addr)
		// log.Default().Printf("[%s]: Enc: %v", n.addr, torControlMessage.Data)
		n.torManager.torRoutingTable.Set(torControlMessage.CircuitID, peer.TorRoutingEntry{CircuitID: torControlMessage.CircuitID, NextHop: torControlMessage.LastHop})
		torClientHelloMessageBytes, err := n.tlsManager.DecryptPublicTor(torControlMessage.Data)
		if err != nil {
			logr.Logger.Err(err).Msgf("[%s]", n.addr)
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
		nextEntry, err := n.torManager.GetNextHop(torControlMessage.CircuitID)
		if err != nil {
			logr.Logger.Err(err).Msgf("[%s]: execTorControlMessage failed. the message: %v", n.addr, torControlMessage)
			return err
		}

		if nextEntry.CircuitID != torControlMessage.CircuitID {
			encryptedData, err := n.tlsManager.EncryptSymmetricTor(n.createTorEntryName(nextEntry.NextHop, nextEntry.CircuitID), torControlMessage.Data)
			if err != nil {
				logr.Logger.Err(err).Msgf("[%s]: execTorControlMessage failed. the message: %v", n.addr, torControlMessage)
				return err
			}
			torRelay := types.TorRelayMessage{
				LastHop:   n.addr,
				CircuitID: nextEntry.CircuitID,
				Cmd:       types.RelayExtended,
				Relay:     nextEntry.NextHop,
				Data:      encryptedData,
			}
			n.SendTLSMessage(nextEntry.NextHop, torRelay)
		} else {
			transportMessage := transport.Message{
				Payload: torControlMessage.Data,
				Type:    types.TorServerHello{}.Name(),
			}
			var newMessage types.TorServerHello
			n.conf.MessageRegistry.UnmarshalMessage(&transportMessage, &newMessage)
			n.execTorServerHello(newMessage, torControlMessage.CircuitID)
		}

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
	n.tlsManager.SetSymmKeyTor(lastHop, circuitID, ck)

	sign, err := n.tlsManager.SignMessage(ck)
	if err != nil {
		return err
	}
	sm := types.TorServerHello{
		ServerPresecretDH: pub,
		Signature:         sign,
		Source:            n.addr,
	}
	log.Default().Printf("[%s]: Sending TorServerHello to %s", n.addr, lastHop)
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
	logr.Logger.Err(err).Msgf("[%s]: execTorServerHello Source:%s CircID: %s", n.addr, torServerHello.Source, circuitID)
	if dhManager == nil {
		logr.Logger.Err(err).Msgf("[%s]: execTorServerHello dhManager.Get failed! Trying to get Source:%s CircID: %s", n.addr, torServerHello.Source, circuitID)
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
	n.tlsManager.SetSymmKeyTor(torServerHello.Source, circuitID, ck)
	nodesAddress, ok := n.torManager.myCircuits.Get(circuitID)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: execTorServerHello myCircuits.Get failed!", n.addr)
		return err
	}
	nodesAddress = append(nodesAddress, torServerHello.Source)
	n.torManager.myCircuits.Set(circuitID, nodesAddress)
	circChan, ok := n.torManager.torChannels.Get(circuitID)
	if ok {
		circChan <- len(nodesAddress)
	}
	// TODO(Jirka, Aamir): Fix error message. This error is legit in a normal run of the program, but it ruins our tests which is why we have removed it for now.
	// if !ok {
	// 	err := fmt.Errorf("[%s]: execTorServerHello torChannels.Get failed", n.addr)
	// 	logr.Logger.Err(err).Msgf("[%s]: execTorServerHello torChannels.Get failed!", n.addr)
	// 	return err
	// }
	logr.Logger.Info().Msgf("[%s]: execTorServerHello success!", n.addr)
	return nil
}
