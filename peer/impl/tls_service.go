package impl

import (
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
	return n.processDecryptedTLSMessage(decryptedMessage, pkt)
}

func (n *node) execTLSClientHello(msg types.Message, pkt transport.Packet) error {
	var err error
	TLSClientHello, ok := msg.(*types.TLSClientHello)
	if !ok {
		err = fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(err).Msgf("[%s]: execTLSClientHello failed", n.addr)
		return err
	}
	dh := dhkx.CreateGroup(&TLSClientHello.PrimeDH, &TLSClientHello.GroupDH)
	ck := TLSClientHello.ClientPresecretDH
	key, err := dh.GeneratePrivateKey(nil)
	if err != nil {
		return err
	}
	sk, err := dh.ComputeKey(&ck, key)
	if err != nil {
		return err
	}
	fmt.Printf(sk.String())
	return nil
}

func (n *node) execTLSServerHello(msg types.Message, pkt transport.Packet) error {
	var err error
	TLSServerHello, ok := msg.(*types.TLSServerHello)
	if !ok {
		err = fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(err).Msgf("[%s]: execTLSServerHello failed", n.addr)
		return err
	}
	sk := TLSServerHello.ServerPresecretDH
	fmt.Printf(sk.String())
	return nil

}
