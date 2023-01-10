/*
	Extends the peer package to implement certificate distribution

	Written by Malo RANZETTI
	January 2023
*/

package impl

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

// =============================================================================
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

// =============================================================================
// CertificateCatalog: A thread safe map between a name and a rsa.PublicKey. We allow changes to a certificate once it is inscribed to prevent certificate forgery
type CertificateCatalog struct {
	catalog map[string]rsa.PublicKey
	lock    sync.Mutex
}

// NewCertificateCatalog: Creates a new CertificateCatalog
func (n *node) NewCertificateCatalog() error {

	if n.certificateCatalog != nil {
		return errors.New("certificate catalog already initialized")
	}

	if n.certificateStore == nil {
		return errors.New("certificate store not initialized")
	}

	cc := CertificateCatalog{
		catalog: make(map[string]rsa.PublicKey),
		lock:    sync.Mutex{},
	}

	pub := n.certificateStore.GetPublicKeyPEM()
	cc.AddCertificate(n.addr, pub)
	n.certificateCatalog = &cc
	return nil
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

func (n *node) GetPeerPublicKey(name string) (rsa.PublicKey, error) {
	return n.certificateCatalog.Get(name)
}

// Pem to PublicKey
func PemToPublicKey(p []byte) (*rsa.PublicKey, error) {
	// Decode the PEM
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}

	// Parse the public key
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

// AddCertificate: Adds a new certificate to the catalog.
func (c *CertificateCatalog) AddCertificate(name string, pemBytes []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	publicKey, err := PemToPublicKey(pemBytes)
	if err != nil {
		return err
	}

	// Check if the name is already in use
	val, ok := c.catalog[name]
	// Check if the keys match

	if ok {
		match := bytes.Equal(publicKey.N.Bytes(), val.N.Bytes()) && publicKey.E == val.E
		if !match {
			log.Warn().Msg("detected probable certificate forgery attempt for " + name)
		}
	}

	// Add the new certificate
	c.catalog[name] = *publicKey

	return nil
}

// TotalKnownNodes: Returns the total number of known nodes by the peer
func (n *node) TotalCertifiedPeers() uint {
	// Count the number of nodes in the catalog
	n.certificateCatalog.lock.Lock()
	defer n.certificateCatalog.lock.Unlock()

	// Filter catalog by trusted peers

	return uint(len(n.certificateCatalog.catalog))

}

// BroadcastCertificate: Broadcasts the certificate to all the peers
// Pack the CertificateBroadcastMessage inside a RumorsMessage and broadcast it across the network
func (n *node) BroadcastCertificate() error {
	// Create the CertificateBroadcastMessage
	certificateBroadcastMessage := types.CertificateBroadcastMessage{
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
	certificateBroadcastMessage, ok := msg.(*types.CertificateBroadcastMessage)
	if !ok {
		return errors.New("failed to cast message to CertificateBroadcastMessage")
	}

	// SECURITY MECHANISM: Check if this is a certificate forgery attempt
	// If the message address is this nodes address, then the certificate must be the same as the local one
	rule2_1 := certificateBroadcastMessage.Addr == n.conf.Socket.GetAddress()
	rule2_2 := bytes.Equal(certificateBroadcastMessage.PEM, n.certificateStore.GetPublicKeyPEM())

	if rule2_1 {
		if !rule2_2 {
			log.Warn().Msg("node detected certificate forgery, will fight for " + certificateBroadcastMessage.Addr)
			n.BroadcastCertificate() // Retransmit across the network
		}
		return nil
	}

	if n.conf.VerifyCertificates {
		go n.AwaitCertificateVerification(certificateBroadcastMessage)
	} else {
		// Add the certificate to the catalog
		err := n.certificateCatalog.AddCertificate(certificateBroadcastMessage.Addr, certificateBroadcastMessage.PEM)
		if err != nil {
			return err
		}
	}

	return nil
}

// AwaitCertificateVerification: async await for the certificate verification
func (n *node) AwaitCertificateVerification(init *types.CertificateBroadcastMessage) {

	target := init.Addr
	// Create the challenge
	challenge := []byte("CHALLENGE::" + target + "::" + strconv.FormatInt(time.Now().UnixNano(), 10))

	// Create the CertificateVerifyMessage
	certificateVerifyMessage := types.CertificateVerifyMessage{
		Challenge: challenge,
		Source:    n.addr,
	}

	res := make(chan []byte)
	// Get rsa.PublicKey from BM PEM
	// Parse the public key
	pk, err := PemToPublicKey(init.PEM)
	if err != nil {
		logr.Logger.Error().Err(err).Msg("failed to parse public key")
		return
	}

	n.certificateVerifications.Set(target, res)
	go n.BroadcastPrivatelyInParallel(target, certificateVerifyMessage)
	logr.Logger.Info().Msgf("[%s] sent certificate verification to %s", n.addr, target)

	// Start timer
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case <-timer.C:
		logr.Logger.Warn().Msg("certificate verification timed out for " + target)
	case r := <-res:
		if err != nil {
			logr.Logger.Error().Err(err).Msg("failed to get peer public key")
			return
		}

		hashed := sha256.Sum256(challenge)
		err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, hashed[:], r[:])
		if err != nil {
			logr.Logger.Error().Err(err).Msg("failed to verify certificate")
			return
		}

		logr.Logger.Info().Msgf("[%s] accepted certificate for %s", n.addr, target)

		// Add the certificate to the catalog
		err = n.certificateCatalog.AddCertificate(init.Addr, init.PEM)
		if err != nil {
			logr.Logger.Error().Err(err).Msg("failed to add certificate to catalog")
			return
		}
	}
}

// handleCertificateVerifyMessage: respond to the challenge
func (n *node) handleCertificateVerifyMessage(msg types.Message, pkt transport.Packet) error {
	// Cast the message
	certificateVerifyMessage, ok := msg.(*types.CertificateVerifyMessage)
	if !ok {
		return errors.New("failed to cast message to CertificateVerifyMessage")
	}

	// Get private key
	pk := n.certificateStore.GetPrivateKey()
	hashed := sha256.Sum256(certificateVerifyMessage.Challenge)
	// Sign the challenge
	response, err := rsa.SignPKCS1v15(rand.Reader, &pk, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}

	// Create the CertificateVerifyResponseMessage
	certificateVerifyResponseMessage := types.CertificateVerifyResponseMessage{
		Source:   n.addr,
		Response: response,
	}

	// Send the message
	n.BroadcastPrivatelyInParallel(certificateVerifyMessage.Source, certificateVerifyResponseMessage)

	return nil
}

// handleCertificateVerifyResponseMessage: handle the response to the challenge
func (n *node) handleCertificateVerifyResponseMessage(msg types.Message, pkt transport.Packet) error {
	// Cast the message
	certificateVerifyResponseMessage, ok := msg.(*types.CertificateVerifyResponseMessage)
	if !ok {
		return errors.New("failed to cast message to CertificateVerifyResponseMessage")
	}

	ch, ok := n.certificateVerifications.Get(certificateVerifyResponseMessage.Source)
	if !ok {
		log.Info().Msg("received certificate verification response from unknown source")
		return nil
	}

	ch <- certificateVerifyResponseMessage.Response
	n.certificateVerifications.Remove(certificateVerifyResponseMessage.Source)

	return nil
}

// =============================================================================
// NodeCatalog: Provides a registry of onion nodes.
type NodeCatalog struct {
	lock   sync.Mutex
	values map[string](*rsa.PublicKey)
}

// NewNodeCatalog: Creates a new NodeCatalog
func (n *node) NewNodeCatalog() error {
	if n.nodeCatalog != nil {
		return errors.New("node catalog already exists")
	}

	n.nodeCatalog = &NodeCatalog{
		lock:   sync.Mutex{},
		values: make(map[string](*rsa.PublicKey)),
	}
	return nil
}

// AddNode: Add a node to the onion registry and init trust at 1 if node is not already known
func (n *node) AddOnionNode(name string) error {
	nc := n.nodeCatalog
	nc.lock.Lock()
	defer nc.lock.Unlock()

	_, ok := nc.values[name]
	if ok || name == n.conf.Socket.GetAddress() {
		// Do not add again or self
		return nil
	}
	// Fetch the public key from the certificate catalog
	pk, err := n.certificateCatalog.Get(name)
	if err != nil {
		return err
	}

	// Check if the node already exists in the trust catalog
	if n.trustCatalog.Knows(name) {
		// Only add if the node is not blacklisted
		if n.trustCatalog.IsTrusted(name) {
			nc.values[name] = &pk
		}
		return nil
	}

	nc.values[name] = &pk

	// Add the node to the trust catalog
	err = n.trustCatalog.NewPeer(name)
	if err != nil {
		return err
	}

	return nil
}

// GetRandomOnionNode: Returns a random node from the Onion registry
func (n *node) GetRandomOnionNode() (string, *rsa.PublicKey, error) {
	nc := n.nodeCatalog

	all, err := n.GetAllOnionNodes()
	if err != nil {
		return "", nil, err
	}

	// Get keys
	var keys []string
	for k := range all {
		keys = append(keys, k)
	}

	// use crypto/rand to generate a random index into the keys slice
	randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(keys))))
	if err != nil {
		return "", nil, err
	}

	// Get the node
	name := keys[randIndex.Int64()]
	pk := nc.values[name]

	return name, pk, nil
}

// GetAllOnionNodes: Returns all nodes from the Onion registry
func (n *node) GetAllOnionNodes() (map[string](*rsa.PublicKey), error) {
	nc := n.nodeCatalog
	nc.lock.Lock()
	defer nc.lock.Unlock()

	// Build trusted node list
	var keys []string
	for k := range nc.values {
		// Exclude self
		if k == n.conf.Socket.GetAddress() {
			continue
		}

		// Only add trusted nodes
		if n.trustCatalog.IsTrusted(k) { //TODO: exclude banned nodes
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no onion nodes available")
	}

	// Get the nodes
	nodes := make(map[string](*rsa.PublicKey))
	for _, name := range keys {
		pk := nc.values[name]
		nodes[name] = pk
	}

	return nodes, nil
}

// -----------------------------------------------------------------------------

// RegisterAsOnionNode: Registers the node as an onion transmission node.
func (n *node) RegisterAsOnionNode() error {

	if n.isOnionNode {
		return errors.New("node is already registered as an onion node")
	}

	// Read the private key
	prk := n.certificateStore.GetPrivateKey()

	// Sign the address
	self := n.conf.Socket.GetAddress()
	hashed := sha256.Sum256([]byte(self))
	proof, err := rsa.SignPKCS1v15(rand.Reader, &prk, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}

	// Create the message
	msg := &types.OnionNodeRegistrationMessage{
		Addr:  self,
		Proof: proof,
	}

	// Marshal the message
	br, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		return err
	}

	// Broadcast the message
	err = n.Broadcast(br)
	if err != nil {
		return err
	}

	n.isOnionNode = true
	return nil
}

// HandleOnionNodeRegistrationMessage: Handles an onion node registration message.
func (n *node) HandleOnionNodeRegistrationMessage(msg types.Message, pkt transport.Packet) error {

	// Convert the message
	onionNodeRegistrationMessage, ok := msg.(*types.OnionNodeRegistrationMessage)
	if !ok {
		return errors.New("could not convert message to onion node registration message")
	}

	// Verify the proof
	pk, err := n.certificateCatalog.Get(onionNodeRegistrationMessage.Addr)
	if err != nil {
		return err
	}

	hashed := sha256.Sum256([]byte(onionNodeRegistrationMessage.Addr))
	err = rsa.VerifyPKCS1v15(&pk, crypto.SHA256, hashed[:], onionNodeRegistrationMessage.Proof)
	if err != nil {
		return err
	}

	// Add the node to the onion node catalog
	err = n.AddOnionNode(onionNodeRegistrationMessage.Addr)
	if err != nil {
		return err
	}

	return nil

}

//=============================================================================
// Util

// GetSentMessagesByType: Returns a slice of all sent messages of a given type.
func (n *node) GetSentMessagesByType(class types.Message) []*transport.Message {
	messages := make([]*transport.Message, 0)

	all := n.conf.Socket.GetOuts()
	for _, br := range all {
		if br.Msg.Type != class.Name() {
			continue
		}
		messages = append(messages, br.Msg)
	}
	return messages
}
