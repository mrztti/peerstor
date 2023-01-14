package peer

import "go.dedis.ch/cs438/types"

type TorRoutingEntry struct {
	CircuitID string
	NextHop   string
}

type TorRoutingServices interface {
	TorCreate(addr string, circID string) error
	GetNextHop(circuitID string) (TorRoutingEntry, error)
	AddTorRoutingEntry(incomingCircuitID string, routingEntry TorRoutingEntry)
	GetTorRoutingEntries() map[string]TorRoutingEntry
	GetCircuitIDs() []string
	TorExtend(addr string, circID string) error
	TorRelayRequest(circID string, data []byte) error
	TorSendHTTPRequest(circID string, httpReq types.TorHTTPRequest) error
	TorEstablishCircuit(finalDestination string, circuitLen int) error
}
type TorEncryptServices interface {
	EncryptPublicTor(peerIP string, plaintext []byte) ([]byte, error)
	DecryptPublicTor(ciphertext []byte) ([]byte, error)
	EncryptSymmetricTor(torID string, plaintext []byte) ([]byte, error)
	DecryptSymmetricTor(torID string, cipherText []byte) ([]byte, error)
	GetSymKeys() map[string][]byte
	AwaitDemoResponse() []byte
}
