package impl

import (
	"github.com/google/uuid"
	"go.dedis.ch/cs438/peer"
)

type TorRoutingEntry struct {
	circuitID string
	nextHop   string
}

type TorManager struct {
	addr            string
	torRoutingTable peer.ConcurrentMap[TorRoutingEntry]
}

func CreateTorManager(addr string) *TorManager {
	return &TorManager{
		addr:            addr,
		torRoutingTable: peer.CreateConcurrentMap[TorRoutingEntry](),
	}
}

func (t *TorManager) GetNextHop(circuitID string) TorRoutingEntry {
	routingEntry, _ := t.torRoutingTable.Get(circuitID)
	return routingEntry
}

func (t *TorManager) AddTorRoutingEntry(incomingCircuitID string, routingEntry TorRoutingEntry) {
	t.torRoutingTable.Set(incomingCircuitID, routingEntry)
}

func getNewCircuitID() string {
	return uuid.NewString()
}
