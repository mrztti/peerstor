/*
	Extends the peer to provide an interface to the trust mechanisms

	Written by Malo RANZETTI
	January 2023
*/

package peer

import (
	"crypto/rsa"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type TrustServices interface {
	Trusts(name string) bool
	HasSharedBan(name string) bool
	Ban(name string)
	Trust(name string)

	GetPeerPublicKey(name string) (rsa.PublicKey, error)
	TotalCertifiedPeers() uint
	RegisterAsOnionNode() error
	GetRandomOnionNode() (string, *rsa.PublicKey, error)
	GetAllOnionNodes() (map[string](*rsa.PublicKey), error)

	//Utils
	GetSentMessagesByType(class types.Message) []*transport.Message
}
