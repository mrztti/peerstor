/*
	Extends the peer package to implement security mechanisms for anonymous communication

	Written by Malo RANZETTI
	January 2023
*/

package impl

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// =============================================================================
// TrustCatalog: A thread safe map between a name and a real value.
// The new state is sent on the hook channel every time the trust in a peer changes
type TrustCatalog struct {
	lock      sync.Mutex
	data      map[string]float32
	threshold float32
	hook      chan TrustMapping
}

type TrustMapping map[string]bool

// NewTrustCatalog: Creates a new TrustCatalog for the node
func (n *node) NewTrustCatalog(threshold float32) error {
	if n.trustCatalog != nil {
		return errors.New("trust catalog already initialized")
	}

	hook := n.trustUpdateHook
	if hook == nil {
		return errors.New("trust update hook not initialized")
	}

	tc := &TrustCatalog{
		lock:      sync.Mutex{},
		data:      make(map[string]float32),
		threshold: threshold,
		hook:      hook,
	}

	err := tc.NewPeer(n.conf.Socket.GetAddress())
	if err != nil {
		return err
	}

	n.trustCatalog = tc
	return nil

}

// NewPeer: Init the trust for a new peer, set to 1.0
func (t *TrustCatalog) NewPeer(name string) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Check that the peer is not already in the catalog
	_, ok := t.data[name]
	if ok {
		return errors.New("peer " + name + " already in the catalog")
	}

	t.data[name] = 1.0
	// Broadcast a new vote using the hook
	t.hook <- t.Trusts()
	return nil
}

// Knows: Returns true if the peer is in the catalog
func (t *TrustCatalog) Knows(name string) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	_, ok := t.data[name]
	return ok
}

// IsTrusted: Returns true if the peer is trusted
func (t *TrustCatalog) IsTrusted(name string) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	value, ok := t.data[name]
	if !ok {
		log.Warn().Msg("peer " + name + " not in the trust catalog")
		return false
	}

	return value >= t.threshold
}

// UpdateTrust: Updates the trust value for a peer using a given function
func (t *TrustCatalog) UpdateTrust(name string, update func(float32) float32) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	value, ok := t.data[name]
	if !ok {
		return errors.New("peer " + name + " not in the trust catalog")
	}

	t.data[name] = update(value)
	return nil
}

// Block: Sets the trust value to 0.0
func (t *TrustCatalog) Block(name string) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	_, ok := t.data[name]
	if !ok {
		return errors.New("peer " + name + " not in the trust catalog")
	}

	t.data[name] = 0.0
	return nil
}

// Reset: Resets the trust value to 1.0
func (t *TrustCatalog) Reset(name string) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	_, ok := t.data[name]
	if !ok {
		return errors.New("peer " + name + " not in the trust catalog")
	}

	t.data[name] = 1.0
	return nil
}

// DetectModifications: Detects a change in trust and broadcasts a new vote to the network
func (t *TrustCatalog) DetectModifications(old bool, new bool) {
	if old != new {
		// Broadcast a new vote using the hook
		t.hook <- t.Trusts()
	}
}

// Trusts: Outputs a copy of the entire trust catalog as a map hiding the internal thresholds
func (t *TrustCatalog) Trusts() TrustMapping {
	t.lock.Lock()
	defer t.lock.Unlock()

	trusts := make(map[string]bool)
	for name, value := range t.data {
		trusts[name] = value >= t.threshold
	}

	return trusts
}

// GetProof: Sign the trust catalog and return the signature
func (n *node) SignTrusts() ([]byte, error) {
	trusts := n.trustCatalog.Trusts()

	// Serialize the map to a JSON string
	data, err := json.Marshal(trusts)
	if err != nil {
		return nil, err
	}

	// get private key
	prk := n.certificateStore.GetPrivateKey()
	// sign the trust catalog using the private key
	return rsa.SignPKCS1v15(rand.Reader, &prk, crypto.SHA256, data)
}

// =============================================================================
// TODO: Implement a ban list using a blockchain

//=============================================================================
// Randomized testing security mechanism

// startSecurityMechanism: Starts the security mechanism of the node
func (n *node) startSecurityMechanism(interval time.Duration, timeoutEffect func(float32) float32, timeout time.Duration, corruptionEffect func(float32) float32) {
	//myAddr := n.conf.Socket.GetAddress()
	ticker := time.NewTicker(interval)

	for {
		select {
		case <-ticker.C:
			/*
				TODO: (encapsulate in go routine)
				- Get a set of all the available exit nodes
				- Filter the set to keep only the trusted ones
				- Select a random exit node from the filtered set
				- Pretend we are a middle node and send a message to ourself through the selected exit node
				- If the message is not received after a timeout, update the trust value of the exit node using the timeoutEffect function
				- If the message is corrupted, update the trust value of the exit node using the corruptionEffect function
			*/
		case <-n.quitChannel:
			ticker.Stop()
			return
		}
	}
}
