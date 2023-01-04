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
	"sync"

	"github.com/rs/zerolog/log"
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

// CertificateCatalog: A thread safe map between a name and a rsa.PublicKey. We do not allow changes to a certificate once it is inscribed.
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

// AddCertificate: Adds a new certificate to the catalog. PModifications are prevented once the certificate is added.
func (c *CertificateCatalog) AddCertificate(name string, pemBytes []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Check if the name is already in use
	_, ok := c.catalog[name]
	if ok {
		return errors.New("name " + name + " already in use")
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
