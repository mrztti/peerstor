package impl

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/monnand/dhkx"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type DHManager struct {
	dhGroup *dhkx.DHGroup
	dhKey   *dhkx.DHKey
}
type TLSManager struct {
	addr               string
	symmKeyStore       peer.ConcurrentMap[[]byte]
	asymmetricKeyStore peer.ConcurrentMap[[]byte]
	dhManager          peer.ConcurrentMap[*DHManager]
}

func CreateTLSManager(addr string) *TLSManager {
	return &TLSManager{
		addr:               addr,
		symmKeyStore:       peer.CreateConcurrentMap[[]byte](),
		asymmetricKeyStore: peer.CreateConcurrentMap[[]byte](),
		dhManager:          peer.CreateConcurrentMap[*DHManager](),
	}
}

func (t *TLSManager) GetSymmKey(peerIP string) []byte {
	val, _ := t.symmKeyStore.Get(peerIP)
	return val
}

func (t *TLSManager) SetSymmKey(peerIP string, key []byte) {
	t.symmKeyStore.Set(peerIP, key)
}

func (t *TLSManager) GetAsymmetricKey(peerIP string) []byte {
	val, _ := t.asymmetricKeyStore.Get(peerIP)
	return val
}

func (t *TLSManager) SetAsymmetricKey(peerIP string, key []byte) {
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

	tlsMessage := types.TLSMessage{
		Source:      t.addr,
		Content:     ciphertext,
		Signature:   nil,
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

func (t *TLSManager) EncryptPublic(peerIP string, message transport.Message) (types.Message, error) {
	// TODO: Implement
	return nil, nil
}

func (t *TLSManager) DecryptPublic(peerIP string, message *types.TLSMessageHello) (transport.Message, error) {
	// TODO: Implement
	return transport.Message{}, nil
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
