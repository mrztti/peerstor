/*
	Extends the peer package to implement certificate distribution

	Written by Malo RANZETTI
	January 2023
*/

package types

import "fmt"

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
func (d CertificateBroadcastMessage) NewEmpty() Message {
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

// OnionNodeRegistrationMessage: Node declares that it is willing to be a Onion transmission node.
// Proof is a signature of the node's address.
// The proof makes it harder to forge a registration message.
// - implements types.Message
type OnionNodeRegistrationMessage struct {
	Addr  string
	Proof []byte
}

// -----------------------------------------------------------------------------
// OnionNodeRegistrationMessage

// NewEmpty implements types.Message.
func (o OnionNodeRegistrationMessage) NewEmpty() Message {
	return &OnionNodeRegistrationMessage{}
}

// Name implements types.Message.
func (o OnionNodeRegistrationMessage) Name() string {
	return "onion_node_registration"
}

// String implements types.Message.
func (o OnionNodeRegistrationMessage) String() string {
	return fmt.Sprintf("onion_node_registration{name:%s, proof:%s}", o.Addr, string(o.Proof))
}

// HTML implements types.Message.
func (o OnionNodeRegistrationMessage) HTML() string {
	return o.String()
}
