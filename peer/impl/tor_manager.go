package impl

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"log"

	"github.com/google/uuid"
	"go.dedis.ch/cs438/peer"
)

type TorManager struct {
	addr            string
	torRoutingTable peer.ConcurrentMap[peer.TorRoutingEntry]
	myCircuits      peer.ConcurrentMap[[]string]
	torChannels     peer.ConcurrentMap[chan int]
}

func CreateTorManager(addr string) *TorManager {
	return &TorManager{
		addr:            addr,
		torRoutingTable: peer.CreateConcurrentMap[peer.TorRoutingEntry](),
		myCircuits:      peer.CreateConcurrentMap[[]string](),
		torChannels:     peer.CreateConcurrentMap[chan int](),
	}
}

func (t *TorManager) GetNextHop(circuitID string) (peer.TorRoutingEntry, error) {
	routingEntry, ok := t.torRoutingTable.Get(circuitID)
	if !ok {
		return peer.TorRoutingEntry{}, fmt.Errorf(
			"[%s]: circuitID %s does not exist",
			t.addr,
			circuitID,
		)
	}
	return routingEntry, nil
}

func (n *node) GetTorRoutingEntry(circuitID string) (peer.TorRoutingEntry, error) {
	return n.torManager.GetNextHop(circuitID)
}

func (t *TorManager) AddTorRoutingEntry(
	incomingCircuitID string,
	routingEntry peer.TorRoutingEntry,
) {
	t.torRoutingTable.Set(incomingCircuitID, routingEntry)
}

func (n *node) AddTorRoutingEntry(incomingCircuitID string, routingEntry peer.TorRoutingEntry) {
	n.torManager.AddTorRoutingEntry(incomingCircuitID, routingEntry)
}

func (n *node) GetTorRoutingEntries() map[string]peer.TorRoutingEntry {
	return n.torManager.torRoutingTable.GetCopy()
}

func getNewCircuitID() string {
	return uuid.NewString()
}

func (n *node) EncryptPublicTor(peerIP string, plaintext []byte) ([]byte, error) {
	return n.tlsManager.EncryptPublicTor(peerIP, plaintext)
}

func (n *node) DecryptPublicTor(ciphertext []byte) ([]byte, error) {
	return n.tlsManager.DecryptPublicTor(ciphertext)
}

func (t *TLSManager) EncryptPublicTor(peerIP string, plaintext []byte) ([]byte, error) {
	publicKey, ok := t.GetAsymmetricKey(peerIP).(rsa.PublicKey)
	if publicKey == (rsa.PublicKey{}) || !ok {
		return []byte{}, fmt.Errorf("no public key found for peer %s", peerIP)
	}
	hash := sha256.New()
	msgLen := len(plaintext)
	step := publicKey.Size() - 2*hash.Size() - 2
	rand := rand.Reader
	var encryptedBytes []byte
	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlockBytes, err := rsa.EncryptOAEP(
			hash,
			rand,
			&publicKey,
			plaintext[start:finish],
			nil,
		)
		if err != nil {
			return []byte{}, fmt.Errorf("encryption failed %s %w", peerIP, err)

		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}
	return encryptedBytes, nil
}

func (t *TLSManager) DecryptPublicTor(ciphertext []byte) ([]byte, error) {
	privateKey, ok := t.keyManager.privateKey.(rsa.PrivateKey)
	if !ok || privateKey.Size() == 0 {
		return []byte{}, fmt.Errorf("no private key found for peer %s", t.addr)
	}
	msgLen := len(ciphertext)
	step := privateKey.PublicKey.Size()
	var decryptedBytes []byte
	hash := sha256.New()
	rand := rand.Reader
	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(
			hash,
			rand,
			&privateKey,
			ciphertext[start:finish],
			nil,
		)
		if err != nil {
			return []byte{}, fmt.Errorf("decryption failed %s", t.addr)
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
}

func (n *node) EncryptSymmetricTor(torID string, plaintext []byte) ([]byte, error) {
	return n.tlsManager.EncryptSymmetricTor(torID, plaintext)
}

func (n *node) DecryptSymmetricTor(torID string, ciphertext []byte) ([]byte, error) {
	return n.tlsManager.DecryptSymmetricTor(torID, ciphertext)
}

func (t *TLSManager) EncryptSymmetricTor(torID string, plaintext []byte) ([]byte, error) {
	symmetricKey := t.GetSymmKey(torID)
	log.Default().Printf("[%s]: Encrypting message for %s with key %v", t.addr, torID, symmetricKey)
	if symmetricKey == nil {
		return []byte{}, fmt.Errorf("no symmetric key found for peer %s", torID)
	}

	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return []byte{}, err
	}

	// The IV needs to be unique, but not secure: we will put it at the beginning of the ciphertext unencrypted.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	initialVect := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, initialVect); err != nil {
		return []byte{}, err
	}

	stream := cipher.NewCFBEncrypter(block, initialVect)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// if err != nil {
	// 	return []byte{}, fmt.Errorf("signing failed %s", torID)
	// }

	return ciphertext, nil
}

func (t *TLSManager) DecryptSymmetricTor(torID string, cipherText []byte) ([]byte, error) {
	symmetricKey := t.GetSymmKey(torID)
	log.Default().Printf("[%s]: Decrypt message for %s with key %v", t.addr, torID, symmetricKey)
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return []byte{}, err
	}

	if len(cipherText) < aes.BlockSize {
		return []byte{}, fmt.Errorf(
			"[%s]: Cannot decrypt message from %s, ciphertext too short",
			t.addr,
			torID,
		)
	}
	initialVect := cipherText[:aes.BlockSize]
	plaintext := cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, initialVect)

	stream.XORKeyStream(plaintext, plaintext)

	return plaintext, nil
}

func (n *node) GetCircuitIDs() []string {
	return n.torManager.myCircuits.GetKeys()
}

func (n *node) createTorEntryName(peerIP, circuitID string) string {
	return fmt.Sprintf("tor#%s#%s", circuitID, peerIP)
}

func (n *node) GetSymKeys() map[string][]byte {
	return n.tlsManager.symmKeyStore.GetCopy()
}
