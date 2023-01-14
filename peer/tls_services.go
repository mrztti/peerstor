package peer

import (
	"crypto"

	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

type KeyExchangeServices interface {
	EstablishTLSConnection(addr string) error
	GetSymKey(addr string) []byte
	GetSymKeys() map[string][]byte
	EncryptSymmetric(peerIP string, message transport.Message) (types.TLSMessage, error)
	DecryptSymmetric(message *types.TLSMessage) (transport.Message, error)
	GetPublicKey() crypto.PublicKey
	GetPrivateKey() crypto.PrivateKey
	SetAsmKey(addr string, publicKey crypto.PublicKey)
	GetPublicKeyFromAddr(addr string) crypto.PublicKey
}
type TLSServices interface {
	EncryptPublic(peerIP string, message transport.Message) (types.TLSMessageHello, error)
	DecryptPublic(message *types.TLSMessageHello) (transport.Message, error)
	SendTLSMessage(peerIP string, message types.Message) error
	SignMessage(messageBytes []byte) ([]byte, error)
}
