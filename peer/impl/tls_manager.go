package impl

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/monnand/dhkx"
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

func (t *TLSManager) IntegrityOk(peerIP string, message []byte, signature []byte) bool {
	// TODO: Implement
	return true
}

func (t *TLSManager) DecryptSymmetric(peerIP string, message []byte) (types.Message, error) {
	// TODO: Implement
	return types.EmptyMessage{}, nil
}

func (t *TLSManager) DecryptPublic(peerIP string, message []byte) (types.Message, error) {
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

func (t *TLSManager) EncryptAsymmetric(peerIP string, message transport.Message) (types.TLSMessage, error) {
	publicKey := t.GetAsymmetricKey(peerIP).(rsa.PublicKey)

	if &publicKey == nil {
		return types.TLSMessage{}, fmt.Errorf("no public key found for peer %s", peerIP)
	}

	plaintext := []byte(message.Payload)
	log.Println("Encrypting message for peer", plaintext)
	encryption, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &publicKey, plaintext, nil)
	log.Printf("Encrypted message for peer %s", encryption)
	if err != nil {
		return types.TLSMessage{}, fmt.Errorf("Encryption failed %s", peerIP)
	}
	tlsMessage := types.TLSMessage{
		Source:      t.addr,
		Content:     encryption,
		Signature:   nil,
		ContentType: message.Type}

	return tlsMessage, nil
}

func (t *TLSManager) DecryptAsymmetric(peerIP string, message *types.TLSMessage) (transport.Message, error) {
	privateKey := t.keyManager.privateKey.(rsa.PrivateKey)
	if &privateKey == nil {
		return transport.Message{}, fmt.Errorf("no private key found for peer %s", peerIP)
	}
	ciphertext := message.Content
	decryptedMessage, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &privateKey, ciphertext, nil)
	if err != nil {
		return transport.Message{}, fmt.Errorf("Decryption failed %s", peerIP)
	}
	log.Printf("Decrypted message for peer %s", decryptedMessage)
	transportMessage := transport.Message{
		Type:    message.ContentType,
		Payload: decryptedMessage,
	}
	return transportMessage, nil
}

func (n *node) EncryptAsymmetric(peerIP string, message transport.Message) (types.TLSMessage, error) {
	return n.tlsManager.EncryptAsymmetric(peerIP, message)
}

func (n *node) DecryptAsymmetric(peerIP string, message *types.TLSMessage) (transport.Message, error) {
	return n.tlsManager.DecryptAsymmetric(peerIP, message)
}
