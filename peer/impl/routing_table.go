package impl

import (
	"fmt"
	"math/rand"
	"time"

	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
)

type RoutingTable struct {
	peer.ConcurrentMap[string]
	addr string
}

func CreateRoutingTable(addr string) RoutingTable {
	return RoutingTable{peer.CreateConcurrentMap[string](), addr}
}

func (r *RoutingTable) IsNeighbour(addr string) bool {
	currentRelay, _ := r.Get(addr)
	return currentRelay == addr
}

func (r *RoutingTable) GetRandomNeighbor(forbiddenKeys peer.Set[string]) (string, error) {
	if r.Count() <= len(forbiddenKeys) {
		return "", fmt.Errorf("no more keys available")
	}
	r.RLock()
	defer r.RUnlock()
	neighbourArr := make([]string, 0)
	// This is not guaranteed to be truly random, but I think it should suffice for our purposes
	for key := range r.Items {
		if !forbiddenKeys.Has(key) && r.IsNeighbour(key) {
			neighbourArr = append(neighbourArr, key)
		}
	}
	if len(neighbourArr) == 0 {
		return "", fmt.Errorf("no more keys available")
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(
		len(neighbourArr),
		func(i, j int) { neighbourArr[i], neighbourArr[j] = neighbourArr[j], neighbourArr[i] },
	)
	return neighbourArr[0], nil
}

func (r *RoutingTable) getNeighbourList(forbiddenKeys peer.Set[string]) []string {
	r.RLock()
	defer r.RUnlock()
	var list []string
	for key := range r.Items {
		if !forbiddenKeys.Has(key) && r.IsNeighbour(key) && key != r.addr {
			list = append(list, key)
		}
	}
	return list
}

func (r *RoutingTable) SplitBudgetAmongNeighbours(
	budget uint,
	forbiddenKeys peer.Set[string],
) map[string]uint {
	neighbours := r.getNeighbourList(forbiddenKeys)
	neighboursCount := len(neighbours)
	budgetMap := make(map[string]uint)
	if neighboursCount == 0 {
		logr.Logger.Info().Msg("No neighbours to split budget among")
		return budgetMap
	}
	for budget > 0 {
		// This is not guaranteed to be truly random, but I think it should suffice for our purposes
		for _, neighbour := range neighbours {
			currValue, ok := budgetMap[neighbour]
			if !ok {
				budgetMap[neighbour] = 1
			} else {
				budgetMap[neighbour] = currValue + 1
			}
			budget--
			if budget == 0 {
				break
			}
		}
	}
	return budgetMap
}
