package peer

import (
	"crypto"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type TLSServices interface {
	CreateDHSymmetricKey(addr string) error
	GetSymKey(addr string) []byte
	EncryptSymmetric(peerIP string, message transport.Message) (types.TLSMessage, error)
	DecryptSymmetric(peerIP string, message *types.TLSMessage) (transport.Message, error)
	GetPublicKey() crypto.PublicKey
	GetPrivateKey() crypto.PrivateKey
	SetAsmKey(addr string, publicKey crypto.PublicKey)
	GetPublicKeyFromAddr(addr string) crypto.PublicKey
	EncryptPublic(peerIP string, message transport.Message) (types.TLSMessage, error)
	DecryptPublic(message *types.TLSMessage) (transport.Message, error)
}
