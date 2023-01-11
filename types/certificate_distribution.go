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

// CertificateVerifyMessage: a message containing a challenge to be signed by the peer
//
// - implements types.Message
type CertificateVerifyMessage struct {
	Source    string
	Challenge []byte
}

// -----------------------------------------------------------------------------
// CertificateVerifyMessage

// NewEmpty implements types.Message.
func (d CertificateVerifyMessage) NewEmpty() Message {
	return &CertificateVerifyMessage{}
}

// Name implements types.Message.
func (d CertificateVerifyMessage) Name() string {
	return "certificate_verify"
}

// String implements types.Message.
func (d CertificateVerifyMessage) String() string {
	return fmt.Sprintf("certificate_verify{source:%s, Challenge:%s}", d.Source, string(d.Challenge[:]))
}

// HTML implements types.Message.
func (d CertificateVerifyMessage) HTML() string {
	return d.String()
}

// CertificateVerifyResponseMessage: response to a CertificateVerifyMessage
//
// - implements types.Message
type CertificateVerifyResponseMessage struct {
	Source   string
	Response []byte
}

// -----------------------------------------------------------------------------
// CertificateVerifyResponseMessage

// NewEmpty implements types.Message.
func (d CertificateVerifyResponseMessage) NewEmpty() Message {
	return &CertificateVerifyResponseMessage{}
}

// Name implements types.Message.
func (d CertificateVerifyResponseMessage) Name() string {
	return "certificate_response"
}

// String implements types.Message.
func (d CertificateVerifyResponseMessage) String() string {
	return fmt.Sprintf("certificate_response{source:%s, response:%s}", d.Source, string(d.Response[:]))
}

// HTML implements types.Message.
func (d CertificateVerifyResponseMessage) HTML() string {
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
