package impl

import (
	"go.dedis.ch/cs438/logr"
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
		Data:      encryptedPayload}

	err = n.SendTLSMessage(addr, torControlMessage)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error sending TLSClientHello to %s", n.addr, addr)
		return err
	}
	return nil
}
