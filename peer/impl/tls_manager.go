package impl

import (
	"github.com/monnand/dhkx"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
)

type TLSManager struct {
	symmKeyStore       peer.ConcurrentMap[[]byte]
	asymmetricKeyStore peer.ConcurrentMap[[]byte]
	dhGroup            *dhkx.DHGroup
}

func CreateTLSManager() *TLSManager {
	return &TLSManager{
		symmKeyStore:       peer.CreateConcurrentMap[[]byte](),
		asymmetricKeyStore: peer.CreateConcurrentMap[[]byte](),
		dhGroup:            &dhkx.DHGroup{},
	}
}

func (t *TLSManager) GetSymmKey(peerIP string) []byte {
	val, _ := t.symmKeyStore.Get(peerIP)
	return val
}

func (t *TLSManager) SetSymmKey(peerIP string, key []byte) {
	t.symmKeyStore.Set(peerIP, key)
}

func (t *TLSManager) GetAsymmetricKey(peerIP string) []byte {
	val, _ := t.asymmetricKeyStore.Get(peerIP)
	return val
}

func (t *TLSManager) SetAsymmetricKey(peerIP string, key []byte) {
	t.asymmetricKeyStore.Set(peerIP, key)
}

func (t *TLSManager) IntegrityOk(peerIP string, message []byte, signature []byte) bool {
	// TODO: Implement
	return true
}

func (t *TLSManager) DecryptSymmetric(peerIP string, message []byte) (types.Message, error) {
	// TODO: Implement
	return types.EmptyMessage{}, nil
}

func (t *TLSManager) DecryptPublic(peerIP string, message []byte) (types.Message, error) {
	// TODO: Implement
	return types.EmptyMessage{}, nil
}
