package impl

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"log"

	"github.com/monnand/dhkx"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

const SIGNATURE_SIZE_BYTES = 256

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
	t.symmKeyStore.Set(peerIP, key[:32])
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

func (n *node) EncryptSymmetric(peerIP string, message transport.Message) (types.TLSMessage, error) {
	return n.tlsManager.EncryptSymmetric(peerIP, message)
}

func (n *node) DecryptSymmetric(peerIP string, message *types.TLSMessage) (transport.Message, error) {
	return n.tlsManager.DecryptSymmetric(peerIP, message)
}

func (t *TLSManager) EncryptSymmetric(peerIP string, message transport.Message) (types.TLSMessage, error) {
	symmetricKey := t.GetSymmKey(peerIP)
	log.Default().Printf("[%s]: Encrypting message for %s with key %v", t.addr, peerIP, symmetricKey)
	if symmetricKey == nil {
		return types.TLSMessage{}, fmt.Errorf("no symmetric key found for peer %s", peerIP)
	}
	plaintext := []byte(message.Payload)

	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return types.TLSMessage{}, err
	}

	// The IV needs to be unique, but not secure: we will put it at the beginning of the ciphertext unencrypted.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	initial_vect := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, initial_vect); err != nil {
		return types.TLSMessage{}, err
	}

	stream := cipher.NewCFBEncrypter(block, initial_vect)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// TODO(jl): Unify what we sign with public encryption. I think we should sign the source and the contenttype, too.
	// TODO: This fails right now, investigate why
	signature, err := t.SignMessage(plaintext)
	if err != nil {
		return types.TLSMessage{}, fmt.Errorf("signing failed %s", peerIP)
	}

	tlsMessage := types.TLSMessage{
		Source:      t.addr,
		Content:     ciphertext,
		Signature:   signature,
		ContentType: message.Type,
	}

	return tlsMessage, nil
}

func (t *TLSManager) DecryptSymmetric(peerIP string, message *types.TLSMessage) (transport.Message, error) {
	symmetricKey := t.GetSymmKey(peerIP)
	// TODO: Check integrity!

	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return transport.Message{}, err
	}

	ciphertext := message.Content
	if len(ciphertext) < aes.BlockSize {
		return transport.Message{}, fmt.Errorf("[%s]: Cannot decrypt message from %s, ciphertext too short", t.addr, peerIP)
	}
	initial_vect := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, initial_vect)

	stream.XORKeyStream(ciphertext, ciphertext)

	return transport.Message{
		Type:    message.ContentType,
		Payload: ciphertext,
	}, nil
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
	// TODO(jl): Shouldn't we sign the encrypted message? Also I think we should sign the contenttype as well.
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

func (t *TLSManager) SignMessage(messageBytes []byte) ([]byte, error) {
	hashed := sha256.Sum256(messageBytes)
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

func (t *TLSManager) VerifySignature(messageBytes, signature []byte, peerIP string) bool {
	hashed := sha256.Sum256(messageBytes)
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
