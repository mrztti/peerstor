package peer

import (
	"crypto"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type TLSServices interface {
	CreateDHSymmetricKey(addr string) error
	GetSymKey(addr string) []byte
	GetPublicKey() crypto.PublicKey
	GetPrivateKey() crypto.PrivateKey
	SetAsmKey(addr string, publicKey crypto.PublicKey)
	GetPublicKeyFromAddr(addr string) crypto.PublicKey
	EncryptAsymmetric(peerIP string, message transport.Message) (types.TLSMessage, error)
	DecryptAsymmetric(peerIP string, message *types.TLSMessage) (transport.Message, error)
}
