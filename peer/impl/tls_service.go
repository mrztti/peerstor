package impl

import (
	"fmt"
	"log"

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

func (n *node) AliceSendBob(bobIP string) error {
	// logr.Logger.Info().Msgf("[%s]: Sending TLSClientHello to %s", n.addr, bobIP)
	log.Default().Println("Sending TLSClientHello to ", bobIP)
	dh, err := dhkx.GetGroup(0)
	if err != nil {
		return err
	}
	log.Default().Println("dh created")
	priv, err := dh.GeneratePrivateKey(nil)
	log.Default().Println("priv created")
	log.Default().Println("priv: ", priv)
	if err != nil {
		return err
	}
	dhManager := DHManager{
		dhGroup: dh,
		dhKey:   priv,
	}
	log.Default().Println("dhManager created")
	// Log the DHManager created
	log.Default().Println("dhManager: ", dhManager)
	n.tlsManager.SetDHManagerEntry(bobIP, &dhManager)
	log.Default().Println("dhManager set")
	pub := priv.Bytes()
	// Log the public key
	log.Default().Println("pub: ", pub)
	msg := types.TLSClientHello{
		GroupDH:           dh.G(),
		PrimeDH:           dh.P(),
		ClientPresecretDH: pub,
	}
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(&msg)
	if err != nil {
		return err
	}
	logr.Logger.Info().Msgf("[%s]: Sending TLSClientHello to %s", n.addr, transportMessage)
	err = n.Unicast(bobIP, transportMessage)
	if err != nil {
		return err
	}
	return nil
}

func (n *node) execTLSClientHello(msg types.Message, pkt transport.Packet) error {
	log.Default().Println("execTLSClientHello")
	var err error
	TLSClientHello, ok := msg.(*types.TLSClientHello)
	if !ok {
		err = fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(err).Msgf("[%s]: execTLSClientHello failed", n.addr)
		return err
	}
	dh := dhkx.CreateGroup(TLSClientHello.PrimeDH, TLSClientHello.GroupDH)
	log.Default().Println("dh created")
	priv, _ := dh.GeneratePrivateKey(nil)
	log.Default().Println("priv created")
	dhManager := DHManager{
		dhGroup: dh,
		dhKey:   priv,
	}
	log.Default().Println("dhManager created")
	n.tlsManager.dhManager.Set(pkt.Header.Source, &dhManager)
	log.Default().Println("dhManager set")
	pub := priv.Bytes()
	log.Default().Println("pub: ", pub)
	sm := types.TLSServerHello{
		ServerPresecretDH: pub,
	}
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(&sm)
	if err != nil {
		return err
	}

	err = n.Unicast(pkt.Header.Source, transportMessage)
	log.Default().Println("Unicast sent")
	if err != nil {
		log.Default().Println("Unicast failed")
		return err
	}
	// ToDo(Aamir): send pub to alice

	a := TLSClientHello.ClientPresecretDH
	log.Println("a: ", a)
	aPubKey := dhkx.NewPublicKey(a)
	ck, err := dh.ComputeKey(aPubKey, priv)
	log.Default().Println("ck: ", ck)
	if err != nil {
		return err
	}
	n.tlsManager.SetSymmKey(pkt.Header.Source, ck.Bytes())
	return nil
}

func (n *node) execTLSServerHello(msg types.Message, pkt transport.Packet) error {
	log.Default().Println("execTLSServerHello")
	var err error
	TLSServerHello, ok := msg.(*types.TLSServerHello)
	if !ok {
		err = fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(err).Msgf("[%s]: execTLSServerHello failed", n.addr)
		return err
	}
	dhManager, ok := n.tlsManager.dhManager.Get(pkt.Header.Source)
	if !ok {
		err = fmt.Errorf("no dhManager for %s", pkt.Header.Source)
		logr.Logger.Err(err).Msgf("[%s]: execTLSServerHello failed", n.addr)
		return err
	}
	a := TLSServerHello.ServerPresecretDH
	aPubKey := dhkx.NewPublicKey(a)
	ck, err := dhManager.dhGroup.ComputeKey(aPubKey, dhManager.dhKey)
	if err != nil {
		return err
	}
	log.Default().Println("ck: ", ck)
	n.tlsManager.SetSymmKey(pkt.Header.Source, ck.Bytes())
	return nil
}
