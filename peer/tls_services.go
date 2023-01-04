package peer

import (
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type TLSServices interface {
	CreateDHSymmetricKey(addr string) error
	GetSymKey(addr string) []byte
	EncryptSymmetric(peerIP string, message transport.Message) (types.TLSMessage, error)
	DecryptSymmetric(peerIP string, message *types.TLSMessage) (transport.Message, error)
}
