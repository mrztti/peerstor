package impl

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/monnand/dhkx"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type DHManager struct {
	dhGroup *dhkx.DHGroup
	dhKey   *dhkx.DHKey
}

type KeyManager struct {
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
}
type TLSManager struct {
	addr               string
	symmKeyStore       peer.ConcurrentMap[[]byte]
	asymmetricKeyStore peer.ConcurrentMap[crypto.PublicKey]
	dhManager          peer.ConcurrentMap[*DHManager]
	keyManager         KeyManager
}

func CreateTLSManager(addr string) *TLSManager {
	return &TLSManager{
		addr:               addr,
		symmKeyStore:       peer.CreateConcurrentMap[[]byte](),
		asymmetricKeyStore: peer.CreateConcurrentMap[crypto.PublicKey](),
		dhManager:          peer.CreateConcurrentMap[*DHManager](),
		keyManager:         KeyManager{},
	}
}
func (t *TLSManager) SetOwnKeys(publicKey crypto.PublicKey, privateKey crypto.PrivateKey) {
	t.keyManager.publicKey = publicKey
	t.keyManager.privateKey = privateKey
	t.SetAsymmetricKey(t.addr, publicKey)
}

func (t *TLSManager) GetSymmKey(peerIP string) []byte {
	val, _ := t.symmKeyStore.Get(peerIP)
	return val
}

func (t *TLSManager) SetSymmKey(peerIP string, key []byte) {
	t.symmKeyStore.Set(peerIP, key)
}

func (t *TLSManager) GetAsymmetricKey(peerIP string) crypto.PublicKey {
	val, _ := t.asymmetricKeyStore.Get(peerIP)
	return val
}

func (t *TLSManager) SetAsymmetricKey(peerIP string, key crypto.PublicKey) {
	t.asymmetricKeyStore.Set(peerIP, key)
}

func (t *TLSManager) DecryptSymmetric(peerIP string, message []byte) (types.Message, error) {
	// TODO: Implement
	return types.EmptyMessage{}, nil
}

func (t *TLSManager) GetDHManagerEntry(peerIP string) *DHManager {
	val, _ := t.dhManager.Get(peerIP)
	return val
}

func (t *TLSManager) SetDHManagerEntry(peerIP string, dhManager *DHManager) {
	t.dhManager.Set(peerIP, dhManager)
}

func (n *node) GetSymKey(addr string) []byte {
	return n.tlsManager.GetSymmKey(addr)
}

func (t *TLSManager) EncryptPublic(peerIP string, message transport.Message) (types.TLSMessage, error) {
	publicKey, ok := t.GetAsymmetricKey(peerIP).(rsa.PublicKey)
	if !ok || publicKey == (rsa.PublicKey{}) {
		return types.TLSMessage{}, fmt.Errorf("no public key found for peer %s", peerIP)
	}

	plaintext := []byte(message.Payload)
	encryption, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &publicKey, plaintext, nil)

	if err != nil {
		return types.TLSMessage{}, fmt.Errorf("encryption failed %s", peerIP)
	}
	signature, err := t.SignMessage(plaintext)
	if err != nil {
		return types.TLSMessage{}, fmt.Errorf("signing failed %s", peerIP)
	}
	tlsMessage := types.TLSMessage{
		Source:      t.addr,
		Content:     encryption,
		Signature:   signature,
		ContentType: message.Type}

	return tlsMessage, nil
}

func (t *TLSManager) DecryptPublic(message *types.TLSMessage) (transport.Message, error) {
	privateKey, ok := t.keyManager.privateKey.(rsa.PrivateKey)
	if !ok || privateKey.Size() == 0 {
		return transport.Message{}, fmt.Errorf("no private key found for peer %s", t.addr)
	}
	ciphertext := message.Content
	decryptedMessage, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &privateKey, ciphertext, nil)
	if err != nil {
		return transport.Message{}, fmt.Errorf("decryption failed %s", t.addr)
	}
	verified := t.VerifySignature(decryptedMessage, message.Signature, message.Source)
	if !verified {
		return transport.Message{}, fmt.Errorf("signature verification failed %s", t.addr)
	}
	transportMessage := transport.Message{
		Type:    message.ContentType,
		Payload: decryptedMessage,
	}
	return transportMessage, nil
}

func (t *TLSManager) SignMessage(message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	privateKey, ok := t.keyManager.privateKey.(rsa.PrivateKey)
	if !ok || privateKey.Size() == 0 {
		return nil, fmt.Errorf("no private key found for peer %s", t.addr)
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, &privateKey, crypto.SHA256, hashed[:])

	if err != nil {
		return nil, fmt.Errorf("encryption failed %s", t.addr)
	}
	return signature, nil
}

func (t *TLSManager) VerifySignature(message, signature []byte, peerIP string) bool {
	hashed := sha256.Sum256(message)
	publicKey, ok := t.GetAsymmetricKey(peerIP).(rsa.PublicKey)
	if !ok || publicKey == (rsa.PublicKey{}) {
		logr.Logger.Warn().Msgf("[%s]: No public key found for %s", t.addr, peerIP)
		return false
	}
	err := rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hashed[:], signature)
	return err == nil
}

func (n *node) EncryptPublic(peerIP string, message transport.Message) (types.TLSMessage, error) {
	return n.tlsManager.EncryptPublic(peerIP, message)
}

func (n *node) DecryptPublic(message *types.TLSMessage) (transport.Message, error) {
	return n.tlsManager.DecryptPublic(message)
}
