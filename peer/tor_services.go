package peer

type TorRoutingEntry struct {
	CircuitID string
	NextHop   string
}

type TorServices interface {
	TorCreate(addr string, circID string) error
	GetNextHop(circuitID string) (TorRoutingEntry, error)
	AddTorRoutingEntry(incomingCircuitID string, routingEntry TorRoutingEntry)
	GetTorRoutingEntries() map[string]TorRoutingEntry
	GetCircuitIDs() []string
	TorExtend(addr string, circID string) error
	EncryptPublicTor(peerIP string, plaintext []byte) ([]byte, error)
	DecryptPublicTor(ciphertext []byte) ([]byte, error)
	EncryptSymmetricTor(torID string, plaintext []byte) ([]byte, error)
	DecryptSymmetricTor(torID string, cipherText []byte) ([]byte, error)
	GetSymKeys() map[string][]byte
	TorRelayRequest(circID string, data []byte) error
	TorEstablishCircuit(finalDestination string, circuitLen int) error
}
