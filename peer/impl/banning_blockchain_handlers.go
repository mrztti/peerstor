package impl

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/types"
)

// BuildProof: Signs a vote by using PKCS1v15 on the concatenation of the address, the target and the Paxos step
func (n *node) BuildProof(target string, phase string) ([]byte, error) {
	data := n.addr + target + fmt.Sprint(n.banPaxos.currentStep.Get()) + phase
	pk := n.certificateStore.GetPrivateKey()
	hashed := sha256.Sum256([]byte(data))
	//Log the hash and the node
	logr.Logger.Trace().Str("Hash", hex.EncodeToString(hashed[:])).Str("Node", n.addr).
		Str("DATA", data).Msgf("Generated proof")
	proof, err := rsa.SignPKCS1v15(rand.Reader, &pk, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	return proof, nil
}

// VerifyProof: Verifies a proof by using PKCS1v15 on the concatenation of the address, the target and the Paxos step
func (n *node) VerifyProof(proof []byte, target string, addr string, phase string) bool {
	// Check nil values
	if proof == nil || target == "" || addr == "" {
		logr.Logger.Error().Msgf("Unable to verify proof - Received nil values")
		return false
	}

	data := addr + target + fmt.Sprint(n.banPaxos.currentStep.Get()) + phase
	pk, err := n.GetPeerPublicKey(addr)
	if err != nil {
		logr.Logger.Error().Err(err).Msgf("Unable to get peer public key")
		return false
	}
	hashed := sha256.Sum256([]byte(data))
	//Log the hash and the node

	err = rsa.VerifyPKCS1v15(&pk, crypto.SHA256, hashed[:], proof)
	logr.Logger.Info().
		Str("Hash", hex.EncodeToString(hashed[:])).
		Str("TARGET", target).
		Str("FROM", addr).
		Str("VALID", strconv.FormatBool(err == nil)).
		Msgf("[%s] Verifying %s :", n.addr, phase)
	if err != nil {
		logr.Logger.Error().Err(err).Msgf("Unable to verify proof")
		return false
	}

	return true
}

func (n *node) handleBanPrepareMessage(prepareMessage *types.BanPaxosPrepareMessage) {
	currentPaxosInstance := n.banPaxos.currentPaxosInstance
	// *PART 1:* Ignore messages

	currentStep := n.banPaxos.currentStep.Get()
	// Ignore messages whose Step ﬁeld do not match your current logical clock (
	if prepareMessage.Step != currentStep {
		logr.Logger.Trace().
			Msgf("[%s] Ignoring PREPARE message (Step mismatch). prepareMessage.Step: %d, n.banPaxos.currentStep: %d",
				n.addr, prepareMessage.Step, currentStep)
		return
	}
	//	Ignore messages whose ID is not greater than MaxID, the previously highest ID you have observed within this step
	if !(prepareMessage.ID > currentPaxosInstance.maxID.Get()) {
		logr.Logger.Trace().
			Msgf("[%s] Ignoring PREPARE message (ID too small). prepareMessage.ID: %d, currentPaxosInstance.maxID: %d",
				n.addr, prepareMessage.ID, currentPaxosInstance.maxID.Get())
		return
	}

	// SPECIAL TO BAN PAXOS: Ignore messages who try to ban a node that we trust
	if n.Trusts(prepareMessage.Target) {
		logr.Logger.Trace().Msgf("[%s]: IGNORING PREPARE message (Value is trusted) : %s",
			n.banPaxos.addr, prepareMessage.Target)
		return
	}

	// *PART 2:* Update MaxID
	currentPaxosInstance.maxID.SetToMax(prepareMessage.ID)

	// *PART 3:* Send promise message
	promiseMessage, err := n.prepareBanPromiseMessage(prepareMessage, currentPaxosInstance)
	if err != nil {
		logr.Logger.Error().Err(err).Msgf("[%s]: Unable to prepare promise message", n.addr)
		return
	}
	logr.Logger.Trace().
		Msgf("[%s]: Sending promise %#v to %s, current step is: %d",
			n.addr, promiseMessage, prepareMessage.Source, currentStep)

	go n.BroadcastPrivatelyInParallel(prepareMessage.Source, promiseMessage)

}

func (n *node) handleBanProposeMessage(proposeMessage *types.BanPaxosProposeMessage) {
	currentPaxosInstance := n.banPaxos.currentPaxosInstance

	// *PART 1:* Ignore messages
	// Ignore messages whose Step ﬁeld do not match your current logical clock (
	if proposeMessage.Step != uint(n.banPaxos.currentStep.Get()) {
		logr.Logger.Trace().
			Msgf("[%s] Ignoring PROPOSE message (Step mismatch). proposeMessage.Step: %d, n.banPaxos.currentStep: %d",
				n.addr, proposeMessage.Step, n.banPaxos.currentStep.Get())
		return
	}

	//  Ignore messages whose ID isn't equal to the highest you have observed within this step (MaxID)
	if proposeMessage.ID != currentPaxosInstance.maxID.Get() {
		logr.Logger.Trace().
			Msgf("[%s]: IGNORING PROPOSE message (MaxID mismatch). proposeMessage.ID: %d, currentPaxosInstance.maxID: %d",
				n.banPaxos.addr, proposeMessage.ID, currentPaxosInstance.maxID.Get())
		return
	}

	// SPECIAL TO BAN PAXOS: Ignore messages who try to ban a node that we trust
	if n.Trusts(proposeMessage.Value.Filename) {
		logr.Logger.Trace().Msgf("[%s]: IGNORING PROPOSE message (Value is trusted) : %s",
			n.banPaxos.addr, proposeMessage.Value.Filename)
		return
	}

	// *PART 2:* Update Accepted Values
	currentPaxosInstance.acceptedID.Set(proposeMessage.ID)
	currentPaxosInstance.acceptedValue = &proposeMessage.Value

	// Generate proof
	proof, err := n.BuildProof(proposeMessage.Value.Filename, "accept")
	if err != nil {
		logr.Logger.Error().Err(err).Msgf("[%s]: Unable to build proof", n.addr)
	}

	// *PART 3:* Broadcast accept message
	acceptMessage := &types.BanPaxosAcceptMessage{
		Step:   uint(n.banPaxos.currentStep.Get()),
		ID:     proposeMessage.ID,
		Value:  proposeMessage.Value,
		Proof:  proof,
		Source: n.addr,
	}
	logr.Logger.Trace().Msgf("[%s]: Broadcasting accept %#v", n.addr, acceptMessage)
	// Broadcast concurrently else we will deadlock
	go n.BroadcastTypesInParallel(acceptMessage)
}

func (n *node) handleBanProposePhase1Message(phase1Message *BanProposePhase1Message) {
	currentPaxosInstance := n.banPaxos.currentPaxosInstance
	currentStep := uint(n.banPaxos.currentStep.Get())
	paxosValue := phase1Message.value
	proposedID := currentPaxosInstance.getNextPaxosID()
	prepareMessage := types.BanPaxosPrepareMessage{
		Step:   currentStep,
		ID:     proposedID,
		Source: n.banPaxos.addr,
		Target: paxosValue.Filename,
	}
	logr.Logger.Trace().
		Msgf(`[%s] Handling PROPOSER_PHASE_1_REQUEST message. Current step: %d, current paxos ID: %d.
	Current proposingPhase %s, phase1responsecount: %d. Proposing name %s`,
			n.addr, currentStep, prepareMessage.ID, currentPaxosInstance.proposingPhase,
			len(currentPaxosInstance.phase1Responses),
			paxosValue.Filename)
	currentPaxosInstance.proposingPhase = phase1Const
	currentPaxosInstance.phase1Responses = make([]types.Message, 0)
	currentPaxosInstance.proposedValue = paxosValue

	go n.BroadcastTypesInParallel(prepareMessage)
}

func (n *node) handleBanPromiseMessage(promiseMessage *types.BanPaxosPromiseMessage) {
	currentPaxosInstance := n.banPaxos.currentPaxosInstance
	currentStep := uint(n.banPaxos.currentStep.Get())
	myProposedID := currentPaxosInstance.lastUsedPaxosID
	logr.Logger.Trace().
		Msgf(`[%s]: Starting to handle promise message. Current step is: %d, our proposed id is %d
	we so far have %d reponses. Received message: %#v`,
			n.addr, currentStep, myProposedID, len(currentPaxosInstance.phase1Responses), promiseMessage)

	// *PART 1:* Ignore messages
	// Ignore messages whose Step ﬁeld do not match your current logical clock (
	if promiseMessage.Step != currentStep {
		logr.Logger.Trace().
			Msgf("[%s] Ignoring PROMISE message (Step mismatch). promiseMessage.Step: %d, n.banPaxos.currentStep: %d",
				n.addr, promiseMessage.Step, n.banPaxos.currentStep.Get())
		return
	}
	// Ignore messages if we are not in phase 1 of proposing
	if currentPaxosInstance.proposingPhase != phase1Const {
		logr.Logger.Trace().
			Msgf("[%s]: Ignoring PROMISE message (not in phase 1). Current phase: %s",
				n.addr, currentPaxosInstance.proposingPhase)
		return
	}
	// Ignore messages that do not match our proposal ID
	if myProposedID != promiseMessage.ID {
		logr.Logger.Trace().
			Msgf("[%s]: Ignoring PROMISE message (ID mismatch). Current ID: %d, promiseMessage.ID: %d",
				n.addr, myProposedID, promiseMessage.ID)
		return
	}

	// Check the proof of incoming messages and discard repeated votes.
	val, ok := currentPaxosInstance.nodesPromised.Get(promiseMessage.Source)
	hasAlreadyPromised := ok && val >= promiseMessage.AcceptedID
	canProve := n.VerifyProof(
		promiseMessage.Proof,
		currentPaxosInstance.proposedValue.Filename,
		promiseMessage.Source,
		"promise",
	)

	if hasAlreadyPromised || !canProve {
		logr.Logger.Info().
			Msgf("[%s]: Ignoring PROMISE message (already promised or can't prove). hasAlreadyPromised: %t, canProve: %t",
				n.addr, hasAlreadyPromised, canProve)
		return
	}
	currentPaxosInstance.nodesPromised.Set(promiseMessage.Source, promiseMessage.AcceptedID)
	// *PART 2a:* Collect promises
	currentPaxosInstance.phase1Responses = append(
		currentPaxosInstance.phase1Responses,
		promiseMessage,
	)
	responseCount := len(currentPaxosInstance.phase1Responses)

	// *PART 2b:* Check if we passed threshold.
	if responseCount >= n.conf.PaxosThreshold(n.conf.TotalPeers) {
		n.InitializeBanPhase2(promiseMessage)
	}
}

func (n *node) InitializeBanPhase2(promiseMessage *types.BanPaxosPromiseMessage) {
	currentPaxosInstance := n.banPaxos.currentPaxosInstance
	currentStep := uint(n.banPaxos.currentStep.Get())
	myProposedID := currentPaxosInstance.lastUsedPaxosID
	n.banPaxos.skipNextResendTick.Set(true)
	// *PART 3:* We passed threshold. Init phase 2

	// Stop the phase 1 ticker
	if currentPaxosInstance.timeouts.Has(fmt.Sprint(promiseMessage.ID)) {
		logr.Logger.Trace().
			Msgf("[%s] Stopping phase 1 ticker for ID %s", n.addr, fmt.Sprint(promiseMessage.ID))
		phase1Timer, _ := currentPaxosInstance.timeouts.Get(fmt.Sprint(promiseMessage.ID))
		phase1Timer.Stop()
		currentPaxosInstance.timeouts.Remove(fmt.Sprint(promiseMessage.ID))
	}
	// if currentPaxosInstance.proposingPhase == consensusConst {
	// 	logr.Logger.Trace().
	// 		Msgf("[%s]: Ignoring PROMISE message (consensus reached). Current phase: %s",
	// 			n.addr, currentPaxosInstance.proposingPhase)
	// 	return
	// }
	currentPaxosInstance.proposingPhase = "phase2"

	// Get value to send: either highest accepted from received messages
	// or the value we proposed
	var valueToSend = currentPaxosInstance.proposedValue
	var highestAcceptedID uint
	for _, promise := range currentPaxosInstance.phase1Responses {
		cast, ok := promise.(*types.BanPaxosPromiseMessage)
		if !ok {
			logr.Logger.Error().Msgf("[%s]: Failed to cast to BanPaxosPromiseMessage", n.addr)
			continue
		}
		if cast.AcceptedValue != nil && cast.AcceptedID > highestAcceptedID {
			valueToSend = cast.AcceptedValue
			highestAcceptedID = cast.AcceptedID
		}
	}

	proposeMessage := types.BanPaxosProposeMessage{
		Step:  currentStep,
		ID:    myProposedID,
		Value: *valueToSend,
	}
	go n.BroadcastTypesInParallel(proposeMessage)
	logr.Logger.Trace().Msgf("[%s]: Sent PROPOSE message with contents %#v", n.addr, proposeMessage)
}

func (n *node) handleBanAcceptMessage(acceptMessage *types.BanPaxosAcceptMessage) {
	currentPaxosInstance := n.banPaxos.currentPaxosInstance
	currentStep := uint(n.banPaxos.currentStep.Get())
	currentAcceptCounter := currentPaxosInstance.phase2Responses.GetOrSetIfNonExistent(
		acceptMessage.Value.UniqID,
		&AtomicCounter{count: 0},
	)
	logr.Logger.Trace().Msgf(`[%s]: Starting to handle accept message. Current step is: %d,
	we are in phase %s.
	Proposed value ID is %s, filename %s, so far we have %d messages for this value.
	Proposed id of this acceptMessage is %d.
	Received message: %#v`,
		n.addr, currentStep, currentPaxosInstance.proposingPhase,
		acceptMessage.Value.UniqID, acceptMessage.Value.Filename,
		currentAcceptCounter.Get(), acceptMessage.ID, acceptMessage)
	// *PART 1:* Ignore messages
	// Ignore messages whose Step ﬁeld do not match your current logical clock (
	if acceptMessage.Step != currentStep {
		logr.Logger.Trace().
			Msgf("[%s] Ignoring ACCEPT message (Step mismatch). promiseMessage.Step: %d, n.banPaxos.currentStep: %d",
				n.addr, acceptMessage.Step, n.banPaxos.currentStep.Get())
		return
	}

	// Check the proof of incoming messages and discard repeated votes.
	val, ok := currentPaxosInstance.nodesAccepted.Get(acceptMessage.Source)
	hasAlreadyAccepted := ok && val >= acceptMessage.ID
	canProve := n.VerifyProof(acceptMessage.Proof, acceptMessage.Value.Filename,
		acceptMessage.Source, "accept")

	if hasAlreadyAccepted || !canProve {
		logr.Logger.Info().
			Msgf("[%s]: Ignoring ACCEPT message (already accepted or can't prove). hasAlreadyAccepted: %t, canProve: %t",
				n.addr, hasAlreadyAccepted, canProve)
		return
	}
	currentPaxosInstance.nodesAccepted.Set(acceptMessage.Source, acceptMessage.ID)
	/* if currentPaxosInstance.proposingPhase == "phase1" {
		logr.Logger.Trace().
			Msgf("[%s]: Ignoring ACCEPT message (in phase 1). Current phase: %s",
				n.addr, currentPaxosInstance.proposingPhase)
		return
	} */
	// ! Here they say to ignore messages if we are not in phase 2 of proposing
	// but let's see what happens if we ignore this
	currentAcceptCount := currentAcceptCounter.Get()
	if !ok {
		currentAcceptCount = currentAcceptCounter.IncrementAndGet()
	}

	if int(currentAcceptCount) >= n.banPaxos.conf.PaxosThreshold(uint(n.TotalCertifiedPeers())) {
		logr.Logger.Trace().
			Msgf("[%s] We have reached consensus on %s. Accepted id is %d, accepted value is %#v",
				n.addr, acceptMessage.Value.UniqID, acceptMessage.ID, acceptMessage.Value)
		// currentPaxosInstance.acceptedID.Set(acceptMessage.ID)
		// currentPaxosInstance.acceptedValue = &acceptMessage.Value
		currentPaxosInstance.proposingPhase = consensusConst
		if currentPaxosInstance.timeouts.Has(fmt.Sprint(acceptMessage.ID)) {
			phase2Timer, _ := currentPaxosInstance.timeouts.Get(fmt.Sprint(acceptMessage.ID))
			phase2Timer.Stop()
			currentPaxosInstance.timeouts.Remove(fmt.Sprint(acceptMessage.ID))
		}
		// CreateBlock
		newBlock := n.banPaxos.createBlockchainBlock(acceptMessage.Value)
		// Broadcast TLC
		n.BroadcastBanTLCMessageInParallel(currentStep, *newBlock)
	}
}

func (n *node) handleBanTLCMessage(TLC *types.BanTLCMessage) {
	currentStep := n.banPaxos.currentStep.Get()
	var err error
	tlcStep := TLC.Step
	if tlcStep < currentStep {
		logr.Logger.Trace().
			Msgf("[%s] Ignoring TLC message (Past message). TLC.Step: %d, n.banPaxos.currentStep: %d",
				n.addr, TLC.Step, currentStep)
		return
	}

	currentPaxosInstance := n.banPaxos.currentPaxosInstance

	// Check the proof of incoming messages and discard repeated votes.
	seen := currentPaxosInstance.nodesTLC.Has(TLC.Source)
	canProve := n.VerifyProof(TLC.Proof, TLC.Block.Value.Filename,
		TLC.Source, "tlc")

	if seen || !canProve {
		logr.Logger.Info().
			Msgf("[%s]: Ignoring TLC message (already seen or can't prove). seen: %t, canProve: %t",
				n.addr, seen, canProve)
		return
	}
	currentPaxosInstance.nodesTLC.Set(TLC.Source, struct{}{})

	stepCounter := n.banPaxos.TLCCounts.GetOrSetIfNonExistent(
		fmt.Sprint(tlcStep),
		&AtomicCounter{count: 0},
	)
	n.banPaxos.TLCBlocks.Set(fmt.Sprint(tlcStep), &TLC.Block)
	tlcsReceived := stepCounter.IncrementAndGet()
	threshold := n.banPaxos.conf.PaxosThreshold(n.TotalCertifiedPeers())
	logr.Logger.Info().
		Msgf("[%s]: Increased TLC step (%d) counter to %d due to message received. Threshold is %d, currentStep is %d",
			n.addr, tlcStep, tlcsReceived, threshold, currentStep)
	if int(tlcsReceived) >= threshold && currentStep == tlcStep {
		err = n.tryAdvanceBanTLC(false, tlcStep)
	}
	logr.Logger.Trace().Msgf("[%s]: Ending execTLCMessage. TLC advance finished with error: %v. ",
		n.addr, err)
}

func (n *node) tryAdvanceBanTLC(catchup bool, tlcStep uint) error {
	// *PART 1:* Check if we can advance (there is consensus)
	currentStep := n.banPaxos.currentStep.Get()
	stepCounter := n.banPaxos.TLCCounts.GetOrSetIfNonExistent(
		fmt.Sprint(tlcStep),
		&AtomicCounter{count: 0},
	)
	messagesReceivedForTlcStep := stepCounter.Get()
	logr.Logger.Trace().
		Msgf("[%s]: Trying to advance TLC from step %d. Current step is %d. Received %d TLC messages for this tlc step.",
			n.addr, tlcStep, currentStep, messagesReceivedForTlcStep)
	threshold := n.banPaxos.conf.PaxosThreshold(n.banPaxos.conf.TotalPeers)
	if !(int(messagesReceivedForTlcStep) >= threshold && currentStep == tlcStep) {
		// No consensus, abort mission
		logr.Logger.Trace().Msgf("[%s]:No consensus, returning.", n.addr)
		return nil
	}
	// TLC CONSENSUS
	logr.Logger.Trace().Msgf("[%s]: Advancing", n.addr)
	blockRef, ok := n.banPaxos.TLCBlocks.Get(fmt.Sprint(tlcStep))
	if !ok {
		logr.Logger.Fatal().
			Msgf("[%s]: consensus reached but TLC block not found for step %d", n.addr, tlcStep)
		return fmt.Errorf(
			"[%s]: consensus reached but TLC block not found for step %d",
			n.addr,
			tlcStep,
		)
	}

	// *PART 2:* Advance TLC

	// 2.1: Add the block to our own blockchain
	tlcBlock := *blockRef
	// Add block to the chain
	err := n.banPaxos.addBlockToBlockchain(tlcBlock)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error adding block %#v to chain", n.addr, tlcBlock)
	}
	// 2.2 Set name association in naming store and notify the client
	/* n.banPaxos.blockchainStore.Set(tlcBlock.Value.Filename, []byte(tlcBlock.Value.Metahash)) */
	// 2.3 Broadcast TLC if not catchup
	// Even if we're catching up, this aint going to hurt anyone.
	n.BroadcastBanTLCMessageInParallel(currentStep, *blockRef)
	logr.Logger.Info().
		Msgf("[%s]: TLC consensus reached for step %d. Advancing to step %d", n.addr, tlcStep, tlcStep+1)
	// 2.4 Increase its TLC by 1
	n.banPaxos.currentStep.SetToMax(currentStep + 1)

	// 2.4b:
	logr.Logger.Trace().
		Msgf("[%s]: Crating new instance, HW3_test just passed step %d", n.addr, currentStep)
	n.banPaxos.currentPaxosInstance.Reset()
	// 2.5 Try to catchup and advance again
	err = n.tryAdvanceBanTLC(true, tlcStep+1)

	if !catchup {
		// oldInstance.timeouts.ForEach(func(ticker *time.Timer) {
		// 	ticker.Stop()
		// })
		logr.Logger.Trace().
			Msgf("[%s] handleAcceptMessage: all timeouts cleared, notifying consensus", n.addr)
		select {
		case n.banPaxos.consensusChannel <- &blockRef.Value:
			logr.Logger.Trace().
				Msgf("[%s] handleAcceptMessage: notifying consensus reach: read successfully", n.addr)
		default:
			logr.Logger.Trace().
				Msgf("[%s] handleAcceptMessage: notifying consensus reach: no readers for consensus", n.addr)
		}

	}
	return err

}
