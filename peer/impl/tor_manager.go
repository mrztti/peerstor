package impl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
	"go.dedis.ch/cs438/peer"
)

type TorRoutingEntry struct {
	circuitID string
	nextHop   string
}

type TorManager struct {
	addr            string
	torRoutingTable peer.ConcurrentMap[TorRoutingEntry]
	myCircuits      peer.ConcurrentMap[[]string]
}

func CreateTorManager(addr string) *TorManager {
	return &TorManager{
		addr:            addr,
		torRoutingTable: peer.CreateConcurrentMap[TorRoutingEntry](),
		myCircuits:      peer.CreateConcurrentMap[[]string](),
	}
}

func (t *TorManager) GetNextHop(circuitID string) (TorRoutingEntry, error) {
	routingEntry, ok := t.torRoutingTable.Get(circuitID)
	if !ok {
		return TorRoutingEntry{}, fmt.Errorf("[%s]: circuitID %s does not exist", t.addr, circuitID)
	}
	return routingEntry, nil
}

func (t *TorManager) AddTorRoutingEntry(incomingCircuitID string, routingEntry TorRoutingEntry) {
	t.torRoutingTable.Set(incomingCircuitID, routingEntry)
}

func getNewCircuitID() string {
	return uuid.NewString()
}

func (t *TLSManager) EncryptPublicTor(peerIP string, plaintext []byte) ([]byte, error) {
	publicKey, ok := t.GetAsymmetricKey(peerIP).(rsa.PublicKey)
	if !ok || publicKey == (rsa.PublicKey{}) {
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

		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, rand, &publicKey, plaintext[start:finish], nil)
		if err != nil {
			return []byte{}, fmt.Errorf("encryption failed %s %v", peerIP, err)

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

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, rand, &privateKey, ciphertext[start:finish], nil)
		if err != nil {
			return []byte{}, fmt.Errorf("decryption failed %s", t.addr)
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
}
