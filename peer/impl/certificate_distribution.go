/*
	Extends the peer package to implement certificate distribution

	Written by Malo RANZETTI
	January 2023
*/

package impl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

// CertificateStore: Read-only memory store for storing the long lasting public and private certificate keys
// Thread-safe because it is read-only
type CertificateStore struct {
	public  rsa.PublicKey
	private rsa.PrivateKey
	pem     []byte
}

// NewCertificateStore: Creates a new CertificateStore
func GenerateCertificateStore(bits int) (*CertificateStore, error) {

	// Generate the public and private keys using the crypto/rsa package
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate private key")
		return nil, err
	}

	// Extract the public key from the private key
	publicKey := privateKey.PublicKey

	// Encode the public key as PEM
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&publicKey),
		},
	)

	// Create a new CertificateStore
	certificateStore := &CertificateStore{
		public:  publicKey,
		private: *privateKey,
		pem:     publicKeyPEM,
	}

	// Return the new CertificateStore
	return certificateStore, nil
}

// GetPublicKey: Returns the public key
func (c *CertificateStore) GetPublicKey() rsa.PublicKey {
	// Safety copy
	publicKey := rsa.PublicKey{
		N: c.public.N,
		E: c.public.E,
	}

	return publicKey
}

// GetPrivateKey: Returns the private key
func (c *CertificateStore) GetPrivateKey() rsa.PrivateKey {
	// Safety copy
	privateKey := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: c.private.PublicKey.N,
			E: c.private.PublicKey.E,
		},
		D: c.private.D,
	}

	return privateKey
}

// GetPublicKeyPEM: Returns the public key as PEM
func (c *CertificateStore) GetPublicKeyPEM() []byte {
	// Safety copy
	pem := make([]byte, len(c.pem))
	copy(pem, c.pem)

	return pem
}

// CertificateCatalog: A thread safe map between a name and a rsa.PublicKey. We allow changes to a certificate once it is inscribed to prevent certificate forgery
type CertificateCatalog struct {
	catalog map[string]rsa.PublicKey
	lock    sync.Mutex
}

// NewCertificateCatalog: Creates a new CertificateCatalog
func NewCertificateCatalog() *CertificateCatalog {
	return &CertificateCatalog{
		catalog: make(map[string]rsa.PublicKey),
		lock:    sync.Mutex{},
	}
}

// Get: Returns the public key associated with the given name
func (c *CertificateCatalog) Get(name string) (rsa.PublicKey, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	publicKey, ok := c.catalog[name]
	if !ok {
		return rsa.PublicKey{}, errors.New("no public key found for name " + name)
	}

	// Safety copy
	publicKeyCopy := rsa.PublicKey{
		N: publicKey.N,
		E: publicKey.E,
	}

	return publicKeyCopy, nil
}

// AddCertificate: Adds a new certificate to the catalog.
func (c *CertificateCatalog) AddCertificate(name string, pemBytes []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Check if the name is already in use
	_, ok := c.catalog[name]
	if ok {
		log.Warn().Msg("detected probable certificate forgery attempt for " + name)
	}

	// Decode the PEM
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("failed to decode PEM")
	}

	// Parse the public key
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return err
	}

	// Add the new certificate
	c.catalog[name] = *publicKey

	return nil
}

// CertificateBroadcastMessage: a message containing the name of the peer and its public key in PEM format
//
// - implements types.Message
type CertificateBroadcastMessage struct {
	Addr string
	PEM  []byte
}

// -----------------------------------------------------------------------------
// CertificateBroadcastMessage

// NewEmpty implements types.Message.
func (d CertificateBroadcastMessage) NewEmpty() types.Message {
	return &CertificateBroadcastMessage{}
}

// Name implements types.Message.
func (d CertificateBroadcastMessage) Name() string {
	return "certificate_broadcast"
}

// String implements types.Message.
func (d CertificateBroadcastMessage) String() string {
	return fmt.Sprintf("certificate{name:%s, PEM:%s}", d.Addr, string(d.PEM))
}

// HTML implements types.Message.
func (d CertificateBroadcastMessage) HTML() string {
	return d.String()
}

// -----------------------------------------------------------------------------

// BroadcastCertificate: Broadcasts the certificate to all the peers
// Pack the CertificateBroadcastMessage inside a RumorsMessage and broadcast it across the network
func (n *node) BroadcastCertificate() error {
	// Create the CertificateBroadcastMessage
	certificateBroadcastMessage := CertificateBroadcastMessage{
		Addr: n.conf.Socket.GetAddress(),
		PEM:  n.certificateStore.GetPublicKeyPEM(),
	}

	// Marshall the CertificateBroadcastMessage
	msg, err := n.conf.MessageRegistry.MarshalMessage(&certificateBroadcastMessage)
	if err != nil {
		return err
	}

	err = n.Broadcast(msg)
	if err != nil {
		return err
	}

	return nil
}

// HandleCertificateBroadcastMessage: Handles a CertificateBroadcastMessage
func (n *node) HandleCertificateBroadcastMessage(msg types.Message, pkt transport.Packet) error {
	// Cast the message
	certificateBroadcastMessage, ok := msg.(*CertificateBroadcastMessage)
	if !ok {
		return errors.New("failed to cast message to CertificateBroadcastMessage")
	}

	// Add the certificate to the catalog
	err := n.certificateCatalog.AddCertificate(certificateBroadcastMessage.Addr, certificateBroadcastMessage.PEM)
	if err != nil {
		return err
	}

	return nil
}
