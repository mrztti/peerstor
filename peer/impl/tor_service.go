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
	n.torManager.myCircuits.Set(circID, []string{})
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

	encryptedPayload, err := n.tlsManager.EncryptPublicTor(addr, transportMessage.Payload)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error Encrypting TLSClientHello to %s", n.addr, addr)
		return err
	}
	nodesAddress, ok := n.torManager.myCircuits.Get(circID)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: Error getting nodesAdress from myCircuits", n.addr)
		return err
	}
	encryptedPayload, err = n.TorEncrypt(circID, encryptedPayload)
	// iterate in reverse order
	// for i := len(nodesAddress) - 1; i >= 0; i-- {
	// 	logr.Logger.Info().Msgf("[%s]: Encrypting TLSClientHello to %s", n.addr, nodesAddress[i])
	// 	encryptedPayload, err = n.tlsManager.EncryptSymmetricTor(n.createTorEntryName(nodesAddress[i], circID), encryptedPayload)
	// 	if err != nil {
	// 		logr.Logger.Err(err).Msgf("[%s]: Error Encrypting TLSClientHello to %s", n.addr, addr)
	// 		return err
	// 	}
	// }

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
	return nil
}

func (n *node) TorEncrypt(circID string, data []byte) ([]byte, error) {
	var err error
	nodesAddress, ok := n.torManager.myCircuits.Get(circID)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: Error getting nodesAdress from myCircuits", n.addr)
		return []byte{}, err
	}
	for i := len(nodesAddress) - 1; i >= 0; i-- {
		logr.Logger.Info().Msgf("[%s]: Encrypting TLSClientHello to %s", n.addr, nodesAddress[i])
		data, err = n.tlsManager.EncryptSymmetricTor(n.createTorEntryName(nodesAddress[i], circID), data)
		if err != nil {
			logr.Logger.Err(err).Msgf("[%s]: Error Encrypting TLSClientHello to %s", n.addr, nodesAddress[i])
			return []byte{}, err
		}
	}
	return data, nil
}

func (n *node) TorDecrypt(circID string, data []byte) ([]byte, error) {
	var err error
	nodesAddress, ok := n.torManager.myCircuits.Get(circID)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: Error getting nodesAdress from myCircuits", n.addr)
		return []byte{}, err
	}
	for i := 0; i < len(nodesAddress); i++ {
		logr.Logger.Info().Msgf("[%s]: Decrypting TLSClientHello to %s", n.addr, nodesAddress[i])
		data, err = n.tlsManager.DecryptSymmetricTor(n.createTorEntryName(nodesAddress[i], circID), data)
		if err != nil {
			logr.Logger.Err(err).Msgf("[%s]: Error Decrypting TLSClientHello to %s", n.addr, nodesAddress[i])
			return []byte{}, err
		}
	}
	return data, nil
}

func (n *node) TorRelayRequest(addr string, circID string, data []byte) error {
	encryptedPayload, err := n.TorEncrypt(circID, data)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error Encrypting TLSClientHello to %s", n.addr, addr)
		return err
	}
	msg := types.TorRelayMessage{
		LastHop:   n.addr,
		CircuitID: circID,
		Cmd:       types.RelayRequest,
		Data:      encryptedPayload,
	}

	return n.SendTLSMessage(addr, msg)
}
