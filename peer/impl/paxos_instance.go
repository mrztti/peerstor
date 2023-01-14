package impl

import (
	"time"

	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
)

const phase1Const = "phase1"
const consensusConst = "consensus"

type PaxosInstance struct {
	myAddr             string
	myPaxosID          uint
	totalNodeCount     uint
	maxID              AtomicCounter
	acceptedID         AtomicCounter
	acceptedValue      *types.PaxosValue
	proposerRetryTime  time.Duration
	consensusThreshold int
	proposingPhase     string
	lastUsedPaxosID    AtomicCounter
	proposedValue      *types.PaxosValue
	phase1Responses    []types.Message
	phase2Responses    peer.ConcurrentMap[*AtomicCounter]
	timeouts           peer.ConcurrentMap[*time.Timer]
	nodesPromised      peer.ConcurrentMap[uint]
	nodesAccepted      peer.ConcurrentMap[uint]
	nodesTLC           peer.ConcurrentMap[struct{}]
}

func CreatePaxosInstance(myAddr string, conf peer.Configuration) *PaxosInstance {
	return &PaxosInstance{
		myAddr:             myAddr,
		totalNodeCount:     conf.TotalPeers,
		maxID:              AtomicCounter{count: 0},
		acceptedID:         AtomicCounter{count: 0},
		acceptedValue:      nil,
		myPaxosID:          conf.PaxosID,
		proposerRetryTime:  conf.PaxosProposerRetry,
		consensusThreshold: conf.PaxosThreshold(conf.TotalPeers),
		proposingPhase:     "none",
		lastUsedPaxosID:    AtomicCounter{count: 0},
		proposedValue:      nil,
		phase1Responses:    make([]types.Message, 0),
		phase2Responses:    peer.CreateConcurrentMap[*AtomicCounter](),
		timeouts:           peer.CreateConcurrentMap[*time.Timer](),
		nodesPromised:      peer.CreateConcurrentMap[uint](),
		nodesAccepted:      peer.CreateConcurrentMap[uint](),
		nodesTLC:           peer.CreateConcurrentMap[struct{}](),
	}
}

func (p *PaxosInstance) RetryReset() {
	p.phase1Responses = make([]types.Message, 0)
	p.proposedValue = nil
	p.acceptedID = AtomicCounter{count: 0}
	p.acceptedValue = nil
}

func (p *PaxosInstance) Reset() {
	p.maxID = AtomicCounter{count: 0}
	p.acceptedID = AtomicCounter{count: 0}
	p.acceptedValue = nil
	p.proposingPhase = "none"
	p.lastUsedPaxosID = AtomicCounter{count: 0}
	p.proposedValue = nil
	p.phase1Responses = make([]types.Message, 0)
	p.phase2Responses = peer.CreateConcurrentMap[*AtomicCounter]()
	p.timeouts = peer.CreateConcurrentMap[*time.Timer]()
}

func (p *PaxosInstance) getNextPaxosID() uint {
	last := p.lastUsedPaxosID.Get()
	if last == 0 {
		p.lastUsedPaxosID.Set(p.myPaxosID)
	} else {
		p.lastUsedPaxosID.Set(last + p.totalNodeCount)
	}
	return p.lastUsedPaxosID.Get()
}
