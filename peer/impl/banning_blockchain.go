/*
Implementation of a ban list using a blockchain
We use the avaliable implementation and define a block using a PaxosValue
Filename -> Adrress of the banned node
Metahash -> Hash of the banned address

Written by Malo RANZETTI
January 2023
*/package impl

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/types"
)

// HasSharedBan: Check if the node has a shared ban with the given address
func (n *node) HasSharedBan(address string) bool {
	bans, err := n.banPaxos.traverseBlockchain()
	if err != nil {
		logr.Logger.Error().Msgf("Error while traversing the blockchain: %s", err)
		return false
	}

	// Check if the address is in the ban list
	for _, ban := range bans {
		if ban == address {
			return true
		}
	}

	return false
}

/* // VerifyBans: Verify the bans in the blockchain
func (n *node) VerifyBans() {
	bc := n.banPaxos.blockchainStore
} */

//=============================================================================

type BanProposePhase1Message struct {
	value *types.PaxosValue
}

// Name implements types.Message.
func (d BanProposePhase1Message) Name() string {
	return "ban_proposerphase1"
}

func (n *node) prepareBanPromiseMessage(
	prepareMessage *types.BanPaxosPrepareMessage,
	currentPaxosInstance *PaxosInstance,
) (*types.BanPaxosPromiseMessage, error) {
	var acceptedID uint
	if currentPaxosInstance.acceptedValue != nil {
		acceptedID = uint(currentPaxosInstance.acceptedID.Get())
	}
	proof, err := n.BuildProof(prepareMessage.Target, "promise")
	if err != nil {
		logr.Logger.Error().Msgf("Error while building proof: %s", err)
		return nil, err
	}
	return &types.BanPaxosPromiseMessage{
		Step:          prepareMessage.Step,
		ID:            prepareMessage.ID,
		AcceptedID:    acceptedID,
		AcceptedValue: currentPaxosInstance.acceptedValue,
		Proof:         proof,
		Source:        n.addr,
	}, nil
}

//=============================================================================
// Message handlers

// ProposeBan: Propose a ban to the network
func (n *node) ProposeBan(address string) error {
	logr.Logger.Info().Msgf("[%s]: Initiate ban: name: %s. Step is: %d",
		n.addr, address, n.banPaxos.currentStep.Get())

	n.banPaxos.taggingLock.Lock()
	defer n.banPaxos.taggingLock.Unlock()
	// Might need to add direct ban if no peers
	hash := sha256.Sum256([]byte(address))
	// Hex encode
	mh := hex.EncodeToString(hash[:])
	for {
		if n.HasSharedBan(address) {
			logr.Logger.Info().Msgf("[%s]: Address %s is already banned", n.addr, address)
			return nil
		}
		if !n.banPaxos.skipNextResendTick.Get() {
			// time.Sleep(time.Duration((rand.Intn(9))+1) * 100 * time.Millisecond)
			phase1Propose := BanProposePhase1Message{
				value: &types.PaxosValue{
					UniqID:   xid.New().String(),
					Filename: address,
					Metahash: mh,
				},
			}
			logr.Logger.Info().
				Msgf("[%s]: Sending to inner channel: BAN_PROPOSER_PHASE_1_REQUEST with contents %#v", n.addr, phase1Propose)
			n.banPaxosInnerMessageChannel <- &phase1Propose
		}
		n.banPaxos.skipNextResendTick.Set(false)
		select {
		case consensusValue := <-n.banPaxos.consensusChannel:
			logr.Logger.Trace().
				Msgf("[%s]: Consensus reached for ban of %s. We proposed name %s",
					n.addr, consensusValue.Filename, address)
			n.banPaxos.skipNextResendTick.Set(false)
			if consensusValue.Filename != address {
				logr.Logger.Info().
					Msgf("[%s]: Consensus value is not our value, restarting. Current step is %d",
						n.addr, n.banPaxos.currentStep.Get())
				logr.Logger.Trace().Msgf("[%s]: Off to bed", n.addr)
				time.Sleep(1000 * time.Millisecond)
				logr.Logger.Trace().Msgf("[%s]: Awake", n.addr)
				continue
			}
			logr.Logger.Info().
				Msgf("[%s]: Ban has been accepted. Current step is %d",
					n.addr, n.banPaxos.currentStep.Get())
			return nil
		case <-time.After(n.conf.PaxosProposerRetry):
			logr.Logger.Info().Msgf("[%s]: Timeout reached, ban not accepted. Current step is %d",
				n.addr, n.banPaxos.currentStep.Get())
			return nil
		}

	}

}
