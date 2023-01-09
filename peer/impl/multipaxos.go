package impl

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"

	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/storage"
	"go.dedis.ch/cs438/types"
)

type MultiPaxos struct {
	addr                 string
	myPaxosID            uint
	conf                 peer.Configuration
	currentStep          AtomicCounter
	currentPaxosInstance *PaxosInstance
	node                 *node
	blockchainStore      storage.Store
	TLCCounts            peer.ConcurrentMap[*AtomicCounter]
	TLCSentByMe          peer.ConcurrentSet[uint]
	TLCBlocks            peer.ConcurrentMap[*types.BlockchainBlock]
	taggingLock          sync.RWMutex
	consensusChannel     chan *types.PaxosValue
	skipNextResendTick   CBool
}

func CreateMultiPaxos(conf peer.Configuration, node *node) *MultiPaxos {
	addr := node.conf.Socket.GetAddress()
	return &MultiPaxos{
		addr:                 addr,
		myPaxosID:            conf.PaxosID,
		conf:                 conf,
		currentStep:          AtomicCounter{count: 0},
		currentPaxosInstance: CreatePaxosInstance(addr, conf),
		node:                 node,
		blockchainStore:      conf.Storage.GetBlockchainStore(),
		TLCCounts:            peer.CreateConcurrentMap[*AtomicCounter](),
		TLCSentByMe:          peer.CreateConcurrentSet[uint](),
		TLCBlocks:            peer.CreateConcurrentMap[*types.BlockchainBlock](),
		taggingLock:          sync.RWMutex{},
		consensusChannel:     make(chan *types.PaxosValue),
		skipNextResendTick:   CBool{val: false},
	}
}

func (m *MultiPaxos) createBlockchainBlock(value types.PaxosValue) *types.BlockchainBlock {
	prevHash := make([]byte, 32)
	blockIndex := m.currentStep.Get()
	if blockIndex > 0 {
		prevHash = m.blockchainStore.Get(storage.LastBlockKey)
	}
	currHash := createBlockHash(value, blockIndex, prevHash)
	newBlockchainBlock := types.BlockchainBlock{
		Index:    blockIndex,
		Value:    value,
		Hash:     currHash,
		PrevHash: prevHash,
	}
	return &newBlockchainBlock
}

func (m *MultiPaxos) addBlockToBlockchain(block types.BlockchainBlock) error {
	buf, err := block.Marshal()
	currHash := block.Hash
	if err != nil {
		logr.Logger.Err(err).
			Msgf("[%s]: addBlockToBlockchain, error marshaling block %#v", m.addr, block)
		return err
	}
	m.blockchainStore.Set(hex.EncodeToString(currHash), buf)
	m.blockchainStore.Set(storage.LastBlockKey, currHash)
	logr.Logger.Info().
		Msgf("[%s]: addBlockToBlockchain, added value for name %s, mh %s, block %#v",
			m.addr, block.Value.Filename, block.Value.Metahash, block)
	return err
}

func createBlockHash(value types.PaxosValue, index uint, prevhash []byte) []byte {
	bytesToHash := make([]byte, 0)
	bytesToHash = append(bytesToHash, []byte(strconv.Itoa(int(index)))...)
	bytesToHash = append(bytesToHash, []byte(value.UniqID)...)
	bytesToHash = append(bytesToHash, []byte(value.Filename)...)
	bytesToHash = append(bytesToHash, []byte(value.Metahash)...)
	bytesToHash = append(bytesToHash, prevhash...)
	hash := sha256.New()
	hash.Write(bytesToHash)
	return hash.Sum(nil)
}
