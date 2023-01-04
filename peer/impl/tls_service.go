package impl

import (
	"crypto"
	"fmt"

	"github.com/monnand/dhkx"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) processDecryptedTLSMessage(decryptedMessage types.Message, pkt transport.Packet) error {
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(decryptedMessage)
	if err != nil {
		return err
	}
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
	integrityOk := n.tlsManager.IntegrityOk(pkt.Header.Source, TLSMessage.Content, TLSMessage.Signature)
	if !integrityOk {
		err = fmt.Errorf("[%s]: integrity check failed for message from %s", n.addr, pkt.Header.Source)
		return err
	}
	decryptedMessage, err := n.tlsManager.DecryptSymmetric(pkt.Header.Source, TLSMessage.Content)
	if err != nil {
		return err
	}
	return n.processDecryptedTLSMessage(decryptedMessage, pkt)
}

func (n *node) execTLSMessageHello(msg types.Message, pkt transport.Packet) error {
	var err error
	TLSMessageHello, ok := msg.(*types.TLSMessageHello)
	if !ok {
		err = fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(err).Msgf("[%s]: execTLSMessageHello failed", n.addr)
		return err
	}
	/*
		1. Use asymmetric Key pk
		2. Check if encrypt(pk, content) == signature
		3. Decrypt content
		4. Call handler
	*/
	integrityOk := n.tlsManager.IntegrityOk(pkt.Header.Source, TLSMessageHello.Content, TLSMessageHello.Signature)
	if !integrityOk {
		err = fmt.Errorf("[%s]: integrity check failed for message from %s", n.addr, pkt.Header.Source)
		return err
	}
	decryptedMessage, err := n.tlsManager.DecryptPublic(pkt.Header.Source, TLSMessageHello.Content)
	if err != nil {
		return err
	}
	return n.processDecryptedTLSMessage(decryptedMessage, pkt)
}

func (n *node) CreateDHSymmetricKey(addr string) error {
	logr.Logger.Info().Msgf("[%s]: Sending TLSClientHello to %s", n.addr, addr)
	dh, err := dhkx.GetGroup(0)
	if err != nil {
		return err
	}

	priv, err := dh.GeneratePrivateKey(nil)

	if err != nil {
		return err
	}
	dhManager := DHManager{
		dhGroup: dh,
		dhKey:   priv,
	}
	n.tlsManager.SetDHManagerEntry(addr, &dhManager)

	pub := priv.Bytes()

	msg := types.TLSClientHello{
		GroupDH:           dh.G(),
		PrimeDH:           dh.P(),
		ClientPresecretDH: pub,
	}
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(&msg)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error marshaling TLSClientHello to %s", n.addr, addr)
		return err
	}

	err = n.Unicast(addr, transportMessage)
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
	dh := dhkx.CreateGroup(TLSClientHello.PrimeDH, TLSClientHello.GroupDH)
	priv, _ := dh.GeneratePrivateKey(nil)
	dhManager := DHManager{
		dhGroup: dh,
		dhKey:   priv,
	}

	n.tlsManager.dhManager.Set(pkt.Header.Source, &dhManager)
	pub := priv.Bytes()

	sm := types.TLSServerHello{
		ServerPresecretDH: pub,
	}
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(&sm)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error marshaling TLSServerHello to %s", n.addr, pkt.Header.Source)
		return err
	}

	err = n.Unicast(pkt.Header.Source, transportMessage)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error sending TLSServerHello to %s", n.addr, pkt.Header.Source)
		return err
	}

	a := TLSClientHello.ClientPresecretDH

	aPubKey := dhkx.NewPublicKey(a)
	ck, err := dh.ComputeKey(aPubKey, priv)

	if err != nil {
		return err
	}
	n.tlsManager.SetSymmKey(pkt.Header.Source, ck.Bytes())
	return nil
}

func (n *node) execTLSServerHello(msg types.Message, pkt transport.Packet) error {
	var err error
	TLSServerHello, ok := msg.(*types.TLSServerHello)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: execTLSServerHello failed", n.addr)
		return err
	}
	dhManager, ok := n.tlsManager.dhManager.Get(pkt.Header.Source)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: execTLSServerHello dhManager.Get failed!", n.addr)
		return err
	}
	a := TLSServerHello.ServerPresecretDH
	aPubKey := dhkx.NewPublicKey(a)
	ck, err := dhManager.dhGroup.ComputeKey(aPubKey, dhManager.dhKey)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: execTLSServerHello ComputeKey failed!", n.addr)
		return err
	}
	n.tlsManager.SetSymmKey(pkt.Header.Source, ck.Bytes())
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
