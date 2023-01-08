/*
	Extends the peer to provide an interface to the trust mechanisms

	Written by Malo RANZETTI
	January 2023
*/

package peer

import "crypto/rsa"

type TrustServices interface {
	Trusts(name string) bool
	HasSharedBan(name string) bool
	Ban(name string)

	GetPeerPublicKey(name string) (rsa.PublicKey, error)
	TotalKnownNodes() uint32
	RegisterAsOnionNode() error
	GetRandomOnionNode() (string, *rsa.PublicKey, error)
	GetAllOnionNodes() (map[string](*rsa.PublicKey), error)
}
