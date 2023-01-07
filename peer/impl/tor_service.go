package impl

import (
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
)

func (n *node) TorCreate(addr string) error {
	circID := getNewCircuitID()
	dhManager, err := n.DHfirstStep()
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error creating DHManager", n.addr)
		return err
	}
	n.tlsManager.SetDHManagerEntryTor(addr, circID, &dhManager)
	pub := dhManager.dhKey.Bytes()

	msg := types.TorClientHello{
		GroupDH:           dhManager.dhGroup.G(),
		PrimeDH:           dhManager.dhGroup.P(),
		ClientPresecretDH: pub,
	}
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(&msg)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error marshaling TLSClientHello to %s", n.addr, addr)
		return err
	}
	encryptedPayload, err := n.tlsManager.EncryptPublicTor(addr, transportMessage.Payload)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error Encrypting TLSClientHello to %s", n.addr, addr)
		return err
	}
	// TorControlMessage is a wrapper around a transport message
	// that contains the circuit ID
	torControlMessage := types.TorControlMessage{
		CircuitID: circID,
		Cmd:       types.Create,
		Data:      encryptedPayload,
		LastHop:   n.addr}

	err = n.SendTLSMessage(addr, torControlMessage)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error sending TLSClientHello to %s", n.addr, addr)
		return err
	}
	n.torManager.torRoutingTable.Set(circID, peer.TorRoutingEntry{CircuitID: circID, NextHop: addr})
	n.torManager.myCircuits.Set(circID, []string{addr})
	return nil
}

func (n *node) TorExtend(addr string, circID string) error {
	dhManager, err := n.DHfirstStep()
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error creating DHManager", n.addr)
		return err
	}
	n.tlsManager.SetDHManagerEntryTor(addr, circID, &dhManager)
	pub := dhManager.dhKey.Bytes()

	msg := types.TorClientHello{
		GroupDH:           dhManager.dhGroup.G(),
		PrimeDH:           dhManager.dhGroup.P(),
		ClientPresecretDH: pub,
	}
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(&msg)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error marshaling TLSClientHello to %s", n.addr, addr)
		return err
	}
	nodesAddress, ok := n.torManager.myCircuits.Get(circID)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: Error getting nodesAdress from myCircuits", n.addr)
		return err
	}
	encryptedPayload, err := n.tlsManager.EncryptPublicTor(addr, transportMessage.Payload)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error Encrypting TLSClientHello to %s", n.addr, addr)
		return err
	}

	for _, node := range nodesAddress {
		encryptedPayload, err = n.tlsManager.EncryptSymmetricTor(n.createTorEntryName(node, circID), encryptedPayload)
		if err != nil {
			logr.Logger.Err(err).Msgf("[%s]: Error Encrypting TLSClientHello to %s", n.addr, addr)
			return err
		}
	}

	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error Encrypting TLSClientHello to %s", n.addr, addr)
		return err
	}
	// TorControlMessage is a wrapper around a transport message
	// that contains the circuit ID
	torControlMessage := types.TorRelayMessage{
		LastHop:   n.addr,
		CircuitID: circID,
		Relay:     addr,
		Cmd:       types.RelayExtend,
		Data:      encryptedPayload}

	err = n.SendTLSMessage(nodesAddress[0], torControlMessage)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error sending TLSClientHello to %s", n.addr, addr)
		return err
	}
	nodesAddress = append(nodesAddress, addr)
	n.torManager.myCircuits.Set(circID, nodesAddress)
	return nil
}
