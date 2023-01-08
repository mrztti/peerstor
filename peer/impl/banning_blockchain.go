/*
Implementation of a ban list using a blockchain
We use the avaliable implementation and define a block using a PaxosValue
Filename -> Adrress of the banned node
Metahash -> Hash of the banned address

Written by Malo RANZETTI
January 2023
*/
package impl

import (
	"crypto/sha256"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/storage"
	"go.dedis.ch/cs438/types"
)

//=============================================================================
// CommonBanList

type CommonBanList struct {
	storage.Store
	storage storage.Store
	banList map[string]struct{}
}

// Interface definitions
func (b *CommonBanList) Get(key string) []byte {
	return b.storage.Get(key)
}

func (b *CommonBanList) Set(key string, val []byte) {
	b.storage.Set(key, val)
	b.banList[key] = struct{}{}
}

func (b *CommonBanList) Delete(key string) {
	// Deleting from the storage is not allowed
	logr.Logger.Error().Msgf("Deleting from the ban list is not allowed")
}

func (b *CommonBanList) Len() int {
	return b.storage.Len()
}

func (b *CommonBanList) ForEach(f func(key string, val []byte) bool) {
	b.storage.ForEach(f)
}

// CreateBanList creates a new ban list from the storage
func CreateBanList(storage storage.Store) *CommonBanList {
	return &CommonBanList{
		storage: storage,
		banList: make(map[string]struct{}),
	}
}

// IsBanned returns true if the address is banned
// TODO : Check if the address is banned by traversing the blockchain
func (b *CommonBanList) IsBanned(address string) bool {
	_, ok := b.banList[address]
	return ok
}

//=============================================================================

type BanProposePhase1Message struct {
	value *types.PaxosValue
}

// Name implements types.Message.
func (d BanProposePhase1Message) Name() string {
	return "ban_proposerphase1"
}

func (m *MultiPaxos) prepareBanPromiseMessage(
	prepareMessage *types.BanPaxosPrepareMessage,
	currentPaxosInstance *PaxosInstance,
) *types.BanPaxosPromiseMessage {
	var acceptedID uint
	if currentPaxosInstance.acceptedValue != nil {
		acceptedID = uint(currentPaxosInstance.acceptedID.Get())
	}
	return &types.BanPaxosPromiseMessage{
		Step:          prepareMessage.Step,
		ID:            prepareMessage.ID,
		AcceptedID:    acceptedID,
		AcceptedValue: currentPaxosInstance.acceptedValue,
	}
}

//=============================================================================
// Message handlers

// ProposeBan: Propose a ban to the network
func (n *node) ProposeBan(address string) error {
	logr.Logger.Trace().Msgf("[%s]: Initiate ban: name: %s. Step is: %d",
		n.addr, address, n.banPaxos.currentStep.Get())
	defer logr.Logger.Trace().
		Msgf("[%s]: Banning proposal finished for: name: %s. Step is: %d",
			n.addr, address, n.banPaxos.currentStep.Get())

	n.banPaxos.taggingLock.Lock()
	defer n.banPaxos.taggingLock.Unlock()
	// Might need to add direct ban if no peers
	hash := sha256.Sum256([]byte(address))
	mh := string(hash[:])
	for {
		if n.banList.IsBanned(address) {
			log.Warn().Msgf("[%s]: Address %s is already banned", n.addr, address)
			return nil
		}
		if !n.banPaxos.skipNextResendTick.Get() {
			// time.Sleep(time.Duration((rand.Intn(9))+1) * 100 * time.Millisecond)
			phase1Propose := ProposePhase1Message{
				value: &types.PaxosValue{
					UniqID:   xid.New().String(),
					Filename: address,
					Metahash: mh,
				},
			}
			logr.Logger.Trace().
				Msgf("[%s]: Sending to inner channel: PROPOSER_PHASE_1_REQUEST with contents %#v", n.addr, phase1Propose)
			n.banPaxosInnerMessageChannel <- &phase1Propose
			logr.Logger.Trace().
				Msgf("[%s]: PROPOSER_PHASE_1_REQUEST has been read from the channel.", n.addr)
		}
		n.banPaxos.skipNextResendTick.Set(false)
		select {
		case consensusValue := <-n.banPaxos.consensusChannel:
			logr.Logger.Trace().
				Msgf("[%s]: Consensus reached for filename %s, mh %s. We proposed name %s, mh %s",
					n.addr, consensusValue.Filename, consensusValue.Metahash, address, mh)
			n.banPaxos.skipNextResendTick.Set(false)
			if consensusValue.Filename != address || consensusValue.Metahash != mh {
				logr.Logger.Trace().
					Msgf("[%s]: Consensus value is not our value, restarting. Current step is %d",
						n.addr, n.banPaxos.currentStep.Get())
				logr.Logger.Trace().Msgf("[%s]: Off to bed", n.addr)
				time.Sleep(1000 * time.Millisecond)
				logr.Logger.Trace().Msgf("[%s]: Awake", n.addr)
				continue
			}
			logr.Logger.Trace().
				Msgf("[%s]: Ban has been accepted, returning. Current step is %d",
					n.addr, n.banPaxos.currentStep.Get())
			return nil
		case <-time.After(n.conf.PaxosProposerRetry):
			logr.Logger.Trace().Msgf("[%s]: Timeout reached, ban not accepted. Current step is %d",
				n.addr, n.banPaxos.currentStep.Get())
			return nil
		}

	}

}
