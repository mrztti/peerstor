package impl

import (
	"crypto"
	"fmt"

	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) processDecryptedTLSMessage(
	transportMessage transport.Message,
	pkt transport.Packet,
) error {
	newPkt := transport.Packet{
		Header: pkt.Header,
		Msg:    &transportMessage,
	}
	go func() {
		err := n.conf.MessageRegistry.ProcessPacket(newPkt)
		if err != nil {
			logr.Logger.Err(err).Msgf("[%s]: Error processing packet", n.addr)
		}
	}()
	return nil
}

func (n *node) execTLSMessage(msg types.Message, pkt transport.Packet) error {
	var err error
	TLSMessage, ok := msg.(*types.TLSMessage)
	if !ok {
		err = fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(err).Msgf("[%s]: execTLSMessage failed", n.addr)
		return err
	}
	/*
		1. Use symmetric Key pk
		2. Check if encrypt(pk, content) == signature
		3. Decrypt content
		4. Call handler
	*/
	decryptedMessage, err := n.tlsManager.DecryptSymmetric(TLSMessage)
	if err != nil {
		return err
	}
	return n.processDecryptedTLSMessage(decryptedMessage, pkt)
}

func (n *node) execTLSMessageHello(msg types.Message, pkt transport.Packet) error {
	/*
		1. Use asymmetric Key pk
		2. Check if encrypt(pk, content) == signature
		3. Decrypt content
		4. Call handler
	*/
	var err error
	TLSMessageHello, ok := msg.(*types.TLSMessageHello)
	if !ok {
		err = fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(err).Msgf("[%s]: execTLSMessageHello failed", n.addr)
		return err
	}
	decryptedMessage, err := n.tlsManager.DecryptPublic(TLSMessageHello)
	// log.Default().Println("decryptedMessage", decryptedMessage.Payload)
	if err != nil {
		return err
	}
	return n.processDecryptedTLSMessage(decryptedMessage, pkt)
}

func (n *node) CreateDHSymmetricKey(addr string) error {
	logr.Logger.Info().Msgf("[%s]: Sending TLSClientHello to %s", n.addr, addr)

	dhManager, err := n.DHfirstStep()

	if err != nil {
		return err
	}
	n.tlsManager.SetDHManagerEntry(addr, &dhManager)

	pub := dhManager.dhKey.Bytes()

	msg := types.TLSClientHello{
		GroupDH:           dhManager.dhGroup.G(),
		PrimeDH:           dhManager.dhGroup.P(),
		ClientPresecretDH: pub,
		Source:            n.addr,
	}
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(&msg)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error marshaling TLSClientHello to %s", n.addr, addr)
		return err
	}
	encryptedMessage, err := n.tlsManager.EncryptPublic(addr, transportMessage)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error Encrypting TLSClientHello to %s", n.addr, addr)
		return err
	}
	tlsTransportMessage, err := n.conf.MessageRegistry.MarshalMessage(&encryptedMessage)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error marshaling TLSClientHello to %s", n.addr, addr)
		return err
	}
	err = n.Unicast(addr, tlsTransportMessage)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error sending TLSClientHello to %s", n.addr, addr)
		return err
	}
	return nil
}

func (n *node) execTLSClientHello(msg types.Message, pkt transport.Packet) error {
	var err error
	TLSClientHello, ok := msg.(*types.TLSClientHello)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: execTLSClientHello failed", n.addr)
		return err
	}

	dhManager, err := n.DHfirstStepWithParams(TLSClientHello.PrimeDH, TLSClientHello.GroupDH)
	if err != nil {
		return err
	}
	n.tlsManager.SetDHManagerEntry(TLSClientHello.Source, &dhManager)

	pub := dhManager.dhKey.Bytes()

	sm := types.TLSServerHello{
		ServerPresecretDH: pub,
		Source:            n.addr,
	}

	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(&sm)
	if err != nil {
		logr.Logger.Err(err).
			Msgf("[%s]: Error marshaling TLSServerHello to %s", n.addr, pkt.Header.Source)
		return err
	}
	encryptedMessage, err := n.tlsManager.EncryptPublic(pkt.Header.Source, transportMessage)
	if err != nil {
		logr.Logger.Err(err).
			Msgf("[%s]: Error Encrypting TLSServerHello to %s", n.addr, pkt.Header.Source)
		return err
	}
	tlsTransportMessage, err := n.conf.MessageRegistry.MarshalMessage(&encryptedMessage)

	if err != nil {
		logr.Logger.Err(err).
			Msgf("[%s]: Error marshaling TLSServerHello to %s", n.addr, pkt.Header.Source)
		return err
	}

	err = n.Unicast(TLSClientHello.Source, tlsTransportMessage)
	if err != nil {
		logr.Logger.Err(err).
			Msgf("[%s]: Error sending TLSServerHello to %s", n.addr, pkt.Header.Source)
		return err
	}

	a := TLSClientHello.ClientPresecretDH

	ck, err := n.DHsecondStep(dhManager, a)

	if err != nil {
		return err
	}
	if n.GetSymKey(pkt.Header.Source) == nil {
		n.tlsManager.SetSymmKey(pkt.Header.Source, ck)
	}
	return nil
}

func (n *node) execTLSServerHello(msg types.Message, pkt transport.Packet) error {
	var err error
	TLSServerHello, ok := msg.(*types.TLSServerHello)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: execTLSServerHello failed", n.addr)
		return err
	}
	dhManager := n.tlsManager.GetDHManagerEntry(TLSServerHello.Source)
	if dhManager == nil {
		logr.Logger.Err(err).Msgf("[%s]: execTLSServerHello dhManager.Get failed!", n.addr)
		return err
	}
	a := TLSServerHello.ServerPresecretDH
	ck, err := n.DHsecondStep(*dhManager, a)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: execTLSServerHello ComputeKey failed!", n.addr)
		return err
	}
	if n.GetSymKey(TLSServerHello.Source) == nil {
		n.tlsManager.SetSymmKey(TLSServerHello.Source, ck)
	}
	return nil
}

func (n *node) GetPublicKey() crypto.PublicKey {
	return n.tlsManager.keyManager.publicKey
}

func (n *node) GetPrivateKey() crypto.PrivateKey {
	return n.tlsManager.keyManager.privateKey
}

func (n *node) SetAsmKey(addr string, publicKey crypto.PublicKey) {
	n.tlsManager.SetAsymmetricKey(addr, publicKey)
}

func (n *node) GetPublicKeyFromAddr(addr string) crypto.PublicKey {
	return n.tlsManager.GetAsymmetricKey(addr)
}

func (n *node) SendTLSMessage(peerIP string, message types.Message) error {
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(message)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error marshaling TLSMessage to %s", n.addr, peerIP)
		return err
	}
	encryptedMessage, err := n.tlsManager.EncryptSymmetric(peerIP, transportMessage)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error encrypting TLSMessage to %s", n.addr, peerIP)
		return err
	}
	n.BroadcastPrivatelyInParallel(peerIP, encryptedMessage)
	return err
}
