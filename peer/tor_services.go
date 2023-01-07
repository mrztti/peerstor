package peer

type TorRoutingEntry struct {
	CircuitID string
	NextHop   string
}

type TorServices interface {
	TorCreate(addr string) error
	GetNextHop(circuitID string) (TorRoutingEntry, error)
	AddTorRoutingEntry(incomingCircuitID string, routingEntry TorRoutingEntry)
	GetTorRoutingEntries() map[string]TorRoutingEntry
}
