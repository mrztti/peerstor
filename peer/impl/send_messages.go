package impl

import (
	"fmt"
	"strings"

	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) preparePackageToSend(dest string, transportMsg transport.Message) transport.Packet {
	myAddr := n.addr
	header := transport.NewHeader(
		myAddr,
		myAddr,
		dest,
		0,
	)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &transportMsg,
	}
	return pkt
}

func (n *node) UnicastTypes(dest string, msg types.Message, ignoreRoutingTable bool) error {
	// _, ok := msg.(types.RumorsMessage)
	// if ok {
	// 	logr.Logger.Info().Msgf("[%s]:UnicastTypes: Sending rumours message to [%s]", n.addr, dest)
	// }
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s] Error marshalling message", n.addr)
		return err
	}
	if ignoreRoutingTable {
		return n.UnicastNoRoute(dest, transportMessage)
	}
	return n.Unicast(dest, transportMessage)
}

func (n *node) chooseRandomNeighbour(
	forbiddenAddresses peer.Set[string],
	ignoreNeighborLack bool,
) (string, error) {
	randomNeighbour, err := n.routingTable.GetRandomNeighbor(forbiddenAddresses)
	// logr.Logger.Info().Msgf("[%s]: Options to send to: %s", n.addr, n.routingTable.GetCopy())
	// logr.Logger.Info().Msgf("[%s]: Forbidden keys: %v", n.addr, forbiddenAddresses)
	// logr.Logger.Info().Msgf("[%s]: Chose to send to random neighbour: %s", n.addr, randomNeighbour)
	if err != nil && !ignoreNeighborLack &&
		!strings.Contains(err.Error(), "no more keys available") {
		return randomNeighbour, err
	}
	return randomNeighbour, nil
}

func (n *node) SendToRandomNeighbour(
	msg types.Message,
	forbiddenAddresses peer.Set[string],
	ignoreNeighborLack bool,
) error {
	randomNeighbour, err := n.chooseRandomNeighbour(forbiddenAddresses, ignoreNeighborLack)
	if err != nil {
		logr.Logger.Err(err)
		return err
	}
	if randomNeighbour == "" {
		return err
	}
	// logr.Logger.Info().
	// 	Msgf("[%s]: Sending %s to randomly chosen neighbour: %s", n.addr, msg.String(), randomNeighbour)
	return n.UnicastTypes(randomNeighbour, msg, false)
}

func (n *node) SendToRandomNeighbourTransport(
	msg transport.Message,
	forbiddenAddresses peer.Set[string],
	ignoreNeighborLack bool,
) error {
	randomNeighbour, err := n.chooseRandomNeighbour(forbiddenAddresses, ignoreNeighborLack)
	if err != nil {
		logr.Logger.Err(err)
		return err
	}
	if randomNeighbour == "" {
		// logr.Logger.Error().Msgf("[%s]: No random neighbour found", n.addr)
		return err
	}
	// logr.Logger.Info().
	// 	Msgf("[%s]: Sending %s to randomly chosen neighbour: %s", n.addr, msg.Payload, randomNeighbour)
	return n.Unicast(randomNeighbour, msg)
}

// Unicast implements peer.Messaging
func (n *node) UnicastNoRoute(dest string, msg transport.Message) error {
	pkt := n.preparePackageToSend(dest, msg)
	return n.socketSend(dest, pkt)
}

// Unicast implements peer.Messaging
func (n *node) Unicast(dest string, msg transport.Message) error {
	nextHop, ok := n.routingTable.Get(dest)
	if !ok {
		return fmt.Errorf("next hop not found: %s", dest)
	}

	pkt := n.preparePackageToSend(dest, msg)

	return n.socketSend(nextHop, pkt)
}

func (n *node) Broadcast(msg transport.Message) error {
	n.broadcastLock.Lock()
	defer n.broadcastLock.Unlock()
	n.attemptedRumoursSent.IncrementAndGet()
	rumor := n.rumorManager.CreateAndAddOurNewRumor(n.addr, &msg)

	// Part 1: Create Rumors message and send it to a random neighbour
	forbiddenAddresses := peer.NewSet(n.addr)
	rumorMessage := types.RumorsMessage{
		Rumors: []types.Rumor{rumor},
	}

	err := n.SendToRandomNeighbour(rumorMessage, forbiddenAddresses, true)
	if err != nil {
		logr.Logger.Err(err)
		return err
	}

	// Part 2: let's execute the message (the one embedded in a rumor) "locally"
	localPkt := n.preparePackageToSend(n.addr, msg)
	logr.Logger.Trace().
		Msgf(`[%s]: Broadcast done. Will now process our own message locally`, n.addr)
	return n.conf.MessageRegistry.ProcessPacket(localPkt)
}

func (n *node) BroadcastTypesInParallel(msg types.Message) {
	err := n.BroadcastTypes(msg)
	if err != nil {
		logr.Logger.Err(err).
			Msgf("[%s] ProposePhase1: Error broadcasting message %s, Error: %#v", n.addr, msg, err)
	}
}

func (n *node) BroadcastTypes(msg types.Message) error {
	logr.Logger.Trace().Msgf("[%s]:BroadcastTypes: Broadcasting message: %s", n.addr, msg.Name())
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s] Error marshalling message", n.addr)
		return err
	}
	return n.Broadcast(transportMessage)
}

func (n *node) BroadcastPrivatelyInParallel(recipient string, msg types.Message) {
	logr.Logger.Trace().
		Msgf("[%s]:BroadcastPrivately: Broadcasting privately to %s", n.addr, recipient)
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s] Error marshalling message", n.addr)
	}
	recipients := make(map[string]struct{})
	recipients[recipient] = struct{}{}
	privateMessage := types.PrivateMessage{
		Recipients: recipients,
		Msg:        &transportMessage,
	}
	err = n.BroadcastTypes(privateMessage)
	if err != nil {
		logr.Logger.Err(err).
			Msgf("[%s] ProposePhase1: Error broadcasting message %s, Error: %#v", n.addr, msg, err)
	}
}

func (n *node) BroadcastTLCMessageInParallel(Step uint, Block types.BlockchainBlock) {
	if n.paxos.TLCSentByMe.AddWithDuplicateCheck(Step) {
		logr.Logger.Trace().
			Msgf("[%s]:NOT BROADCASTING (duplicate) TLC message for step %d, block %#v", n.addr, Step, Block)
		return
	}
	logr.Logger.Trace().
		Msgf("[%s]:BroadcastTLCMessage: Broadcasting TLC message for step %d, block %#v", n.addr, Step, Block)
	go n.BroadcastTypesInParallel(&types.TLCMessage{
		Step:  Step,
		Block: Block,
	})
}

func (n *node) BroadcastBanTLCMessageInParallel(Step uint, Block types.BlockchainBlock) {
	if n.banPaxos.TLCSentByMe.AddWithDuplicateCheck(Step) {
		logr.Logger.Trace().
			Msgf("[%s]:NOT BROADCASTING (duplicate) TLC message for step %d, block %#v", n.addr, Step, Block)
		return
	}
	logr.Logger.Trace().
		Msgf("[%s]:BroadcastTLCMessage: Broadcasting TLC message for step %d, block %#v", n.addr, Step, Block)

	// Generate proof
	proof, err := n.BuildProof(Block.Value.Filename, "tlc")
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s] Error building proof", n.addr)
		return
	}
	go n.BroadcastTypesInParallel(&types.BanTLCMessage{
		Step:   Step,
		Block:  Block,
		Source: n.addr,
		Proof:  proof,
	})
}

func (n *node) sendAck(origPkt transport.Packet) error {
	msg := types.AckMessage{
		AckedPacketID: origPkt.Header.PacketID,
		Status:        n.rumorManager.GetStatusMessage(),
	}
	return n.UnicastTypes(origPkt.Header.Source, msg, true)
}

func (n *node) socketSend(dest string, pkt transport.Packet) error {
	if pkt.Msg.Type == "rumor" && n.conf.AckTimeout > 0 {
		n.responseManager.StartAckTimeout(pkt.Header.PacketID, dest, pkt.Msg, n.conf.AckTimeout, n)
	}
	return n.conf.Socket.Send(dest, pkt, 0)
}

func (n *node) sendDataRequest(requestID, dest, chunk string, iteration uint) error {
	msg := types.DataRequestMessage{
		Key:       chunk,
		RequestID: requestID,
	}
	err := n.UnicastTypes(dest, msg, false)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error sending data request to %s", n.addr, dest)
		return err
	}
	n.responseManager.StartDataRequestTimeout(requestID, dest, chunk, iteration, n)
	return err
}

func (n *node) sendDataReply(requestID, dest, chunk string, chunkData []byte) error {
	msg := types.DataReplyMessage{
		Key:       chunk,
		RequestID: requestID,
		Value:     chunkData,
	}
	err := n.UnicastTypes(dest, msg, false)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error sending data reply to %s", n.addr, dest)
		return err
	}
	return err
}

func (n *node) sendSearchRequest(
	requestID string,
	requestOrigin string,
	budget uint,
	pattern string,
	forbiddenKeys peer.Set[string],
) error {
	n.responseManager.seenSearchRequests.Add(requestID)
	budgetSplit := n.routingTable.SplitBudgetAmongNeighbours(budget, forbiddenKeys)
	logr.Logger.Info().
		Msgf("[%s]: Sending search request %s with pattern %s and budget %d to %#v",
			n.addr, requestID, pattern, budget, budgetSplit)
	for neighbour, budget := range budgetSplit {
		msg := types.SearchRequestMessage{
			Budget:    budget,
			Origin:    requestOrigin,
			Pattern:   pattern,
			RequestID: requestID,
		}
		err := n.UnicastTypes(neighbour, msg, false)
		if err != nil {
			logr.Logger.Err(err).Msgf("[%s]: Error sending search request to %s", n.addr, neighbour)
			return err
		}
	}
	return nil
}

func (n *node) sendSearchAllReply(
	requestID, dest, nextHop string,
	fileInfos []types.FileInfo,
) error {
	logr.Logger.Trace().
		Msgf("[%s]: Sending search reply to %s via %s with %d file infos", n.addr, dest, nextHop, len(fileInfos))
	msg := types.SearchReplyMessage{
		Responses: fileInfos,
		RequestID: requestID,
	}
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(msg)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s] Error marshalling message", n.addr)
		return err
	}
	pkt := n.preparePackageToSend(dest, transportMessage)
	return n.socketSend(nextHop, pkt)
}
