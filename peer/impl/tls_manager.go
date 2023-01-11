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

	"github.com/monnand/dhkx"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

const SignatureSizeBytes = 256

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

func (t *TLSManager) SetSymmKeyTor(peerIP string, circuitID string, key []byte) {
	t.symmKeyStore.Set("tor#"+circuitID+"#"+peerIP, key[:32])
}

func (t *TLSManager) GetSymmKeyTor(peerIP string, circuitID string) []byte {
	val, _ := t.symmKeyStore.Get("tor#" + circuitID + "#" + peerIP)
	return val
}

func (t *TLSManager) GetAsymmetricKey(peerIP string) crypto.PublicKey {
	val, _ := t.asymmetricKeyStore.Get(peerIP)
	return val
}

func (t *TLSManager) SetAsymmetricKey(peerIP string, key crypto.PublicKey) {
	t.asymmetricKeyStore.Set(peerIP, key)
}

func (n *node) EncryptSymmetric(
	peerIP string,
	message transport.Message,
) (types.TLSMessage, error) {
	return n.tlsManager.EncryptSymmetric(peerIP, message)
}

func (n *node) DecryptSymmetric(message *types.TLSMessage) (transport.Message, error) {
	return n.tlsManager.DecryptSymmetric(message)
}

func (t *TLSManager) EncryptSymmetric(
	peerIP string,
	message transport.Message,
) (types.TLSMessage, error) {
	symmetricKey := t.GetSymmKey(peerIP)
	// log.Default().Printf("[%s]: Encrypting message for %s with key %v", t.addr, peerIP, symmetricKey)
	if symmetricKey == nil {
		return types.TLSMessage{}, fmt.Errorf("no symmetric key found for peer %s", peerIP)
	}
	plaintext := []byte(message.Payload)

	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return types.TLSMessage{}, err
	}

	// The IV needs to be unique, but not secure: we will put it at the beginning of the ciphertext unencrypted.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext)+SignatureSizeBytes)
	initialVect := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, initialVect); err != nil {
		return types.TLSMessage{}, err
	}

	// Sign then encrypt
	signedBytes := concatenateArrays([]byte(t.addr), []byte(message.Type), initialVect, plaintext)
	signature, err := t.SignMessage(signedBytes)
	// log.Default().Printf("Signed bytes: %v", signedBytes)
	// log.Default().Printf("Signature: %v", signature)

	plaintextWithSignature := concatenateArrays(plaintext, signature)
	stream := cipher.NewCFBEncrypter(block, initialVect)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintextWithSignature)

	if err != nil {
		return types.TLSMessage{}, fmt.Errorf("signing failed %s", peerIP)
	}

	tlsMessage := types.TLSMessage{
		Source:           t.addr,
		ContentType:      message.Type,
		SignedCiphertext: ciphertext,
	}

	return tlsMessage, nil
}

func (t *TLSManager) DecryptSymmetric(message *types.TLSMessage) (transport.Message, error) {
	peerIP := message.Source
	symmetricKey := t.GetSymmKey(peerIP)
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return transport.Message{}, err
	}

	cipherTextWithIVAndSignature := message.SignedCiphertext
	if len(cipherTextWithIVAndSignature) < aes.BlockSize {
		return transport.Message{}, fmt.Errorf(
			"[%s]: Cannot decrypt message from %s, ciphertext too short",
			t.addr,
			peerIP,
		)
	}
	initialVect := cipherTextWithIVAndSignature[:aes.BlockSize]
	ciphertextWithSignature := cipherTextWithIVAndSignature[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, initialVect)

	stream.XORKeyStream(ciphertextWithSignature, ciphertextWithSignature)

	// Check integrity
	signatureStartIndex := len(ciphertextWithSignature) - SignatureSizeBytes
	signature := ciphertextWithSignature[signatureStartIndex:]
	plaintext := ciphertextWithSignature[:signatureStartIndex]

	signedBytes := concatenateArrays(
		[]byte(message.Source),
		[]byte(message.ContentType),
		initialVect,
		plaintext,
	)

	signatureOk := t.VerifySignature(signedBytes, signature, peerIP)
	if !signatureOk {
		return transport.Message{}, fmt.Errorf("signature verification failed %s", t.addr)
	}
	return transport.Message{
		Type:    message.ContentType,
		Payload: plaintext,
	}, nil
}

func (t *TLSManager) GetDHManagerEntry(peerIP string) *DHManager {
	val, _ := t.dhManager.Get(peerIP)
	return val
}

func (t *TLSManager) GetDHManagerEntryTor(peerIP, circuitID string) *DHManager {
	return t.GetDHManagerEntry("tor#" + circuitID + "#" + peerIP)
}

func (t *TLSManager) SetDHManagerEntry(peerIP string, dhManager *DHManager) {
	t.dhManager.Set(peerIP, dhManager)
}

func (t *TLSManager) SetDHManagerEntryTor(peerIP, circuitID string, dhManager *DHManager) {
	t.dhManager.Set("tor#"+circuitID+"#"+peerIP, dhManager)
}

func (n *node) GetSymKey(addr string) []byte {
	return n.tlsManager.GetSymmKey(addr)
}

func (t *TLSManager) EncryptPublic(
	peerIP string,
	message transport.Message,
) (types.TLSMessageHello, error) {
	publicKey, ok := t.GetAsymmetricKey(peerIP).(rsa.PublicKey)
	if !ok || publicKey == (rsa.PublicKey{}) {
		return types.TLSMessageHello{}, fmt.Errorf("no public key found for peer %s", peerIP)
	}

	plaintext := []byte(message.Payload)
	signature, err := t.SignMessage(
		concatenateArrays([]byte(t.addr), []byte(message.Type), plaintext),
	)
	if err != nil {
		return types.TLSMessageHello{}, fmt.Errorf("signing failed %s", peerIP)
	}
	plaintextWithSignature := concatenateArrays(plaintext, signature)
	hash := sha256.New()
	msgLen := len(plaintextWithSignature)
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
			plaintextWithSignature[start:finish],
			nil,
		)
		if err != nil {
			return types.TLSMessageHello{}, fmt.Errorf("encryption failed %s %w", peerIP, err)

		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}

	tlsMessage := types.TLSMessageHello{
		Source:           t.addr,
		SignedCiphertext: encryptedBytes,
		ContentType:      message.Type}

	return tlsMessage, nil
}

// sign(plaintext) => plain_sign
// encrypt(plain_sign) => enc_sign || Packet: signature: enc_sign
func (t *TLSManager) DecryptPublic(message *types.TLSMessageHello) (transport.Message, error) {
	privateKey, ok := t.keyManager.privateKey.(rsa.PrivateKey)
	if !ok || privateKey.Size() == 0 {
		return transport.Message{}, fmt.Errorf("no private key found for peer %s", t.addr)
	}
	ciphertext := message.SignedCiphertext
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
			return transport.Message{}, fmt.Errorf("decryption failed %s", t.addr)
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}
	// decryptedMessage, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &privateKey, ciphertext, nil)
	// if err != nil {
	// 	return transport.Message{}, fmt.Errorf("decryption failed %s", t.addr)
	// }
	// log.Default().Println("decryptedBytes", len(decryptedBytes))
	signatureStartIndex := len(decryptedBytes) - SignatureSizeBytes
	// log.Default().Println("signatureStartIndex", signatureStartIndex)
	signature := decryptedBytes[signatureStartIndex:]
	// log.Default().Printf("signature len %d, signature %s", len(signature), signature)
	plaintext := decryptedBytes[:signatureStartIndex]
	// log.Default().Printf("plaintext len %d; plaintext %s", len(plaintext), plaintext)

	signedBytes := concatenateArrays([]byte(message.Source), []byte(message.ContentType), plaintext)

	signatureOk := t.VerifySignature(signedBytes, signature, message.Source)
	if !signatureOk {
		return transport.Message{}, fmt.Errorf("signature verification failed %s", t.addr)
	}
	transportMessage := transport.Message{
		Type:    message.ContentType,
		Payload: plaintext,
	}
	return transportMessage, nil
}

func (t *TLSManager) SignMessage(messageBytes []byte) ([]byte, error) {
	hashed := sha256.Sum256(messageBytes)
	// log.Default().Printf("hashed encrypt %v", hashed)
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
	// log.Default().Printf("hashed decrypt %v", hashed)
	publicKey, ok := t.GetAsymmetricKey(peerIP).(rsa.PublicKey)
	if !ok || publicKey == (rsa.PublicKey{}) {
		logr.Logger.Warn().Msgf("[%s]: No public key found for %s", t.addr, peerIP)
		return false
	}
	// log.Default().Printf("about to verify signature")
	err := rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hashed[:], signature)
	return err == nil
}

func (n *node) EncryptPublic(
	peerIP string,
	message transport.Message,
) (types.TLSMessageHello, error) {
	return n.tlsManager.EncryptPublic(peerIP, message)
}

func (n *node) DecryptPublic(message *types.TLSMessageHello) (transport.Message, error) {
	return n.tlsManager.DecryptPublic(message)
}
func (n *node) SignMessage(messageBytes []byte) ([]byte, error) {
	return n.tlsManager.SignMessage(messageBytes)
}

func concatenateArrays(arrays ...[]byte) []byte {
	var totalLength int
	for _, array := range arrays {
		totalLength += len(array)
	}
	result := make([]byte, totalLength)
	var offset int
	for _, array := range arrays {
		copy(result[offset:], array)
		offset += len(array)
	}
	return result
}
