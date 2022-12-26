package impl

import (
	"fmt"
	"math/rand"
	"sort"

	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

const RumorManagerDebug = false

type RumorList struct {
	Rumors []types.Rumor
}

func CreateRumorsList(rumors ...types.Rumor) *RumorList {
	return &RumorList{
		Rumors: rumors,
	}
}

type RumorManager struct {
	peer.ConcurrentMap[*RumorList]
	addr string
}

func CreateRumorManager(addr string) RumorManager {
	return RumorManager{
		ConcurrentMap: peer.CreateConcurrentMap[*RumorList](),
		addr:          addr,
	}
}

func (r *RumorManager) AddOrGetOrigin(origin string) (*RumorList, bool) {
	r.Lock()
	defer r.Unlock()
	return r.addOrGetOriginInternal(origin)
}

func (r *RumorManager) addOrGetOriginInternal(origin string) (*RumorList, bool) {
	_, alreadyPresent := r.Items[origin]
	if !alreadyPresent {
		r.Items[origin] = CreateRumorsList()
	}
	return r.Items[origin], alreadyPresent
}

func (r *RumorManager) AddRumorInternal(rumor types.Rumor) bool {
	rumorList, _ := r.addOrGetOriginInternal(rumor.Origin)
	if rumor.Sequence != uint(len(rumorList.Rumors))+1 {
		return false
	}
	rumorList.Rumors = append(rumorList.Rumors, rumor)
	if RumorManagerDebug {
		logr.Logger.Info().Msgf("[%s]: RumorManager state: %s\n", r.addr, r.PrintMe())
	}
	return true
}

func (r *RumorManager) CreateAndAddOurNewRumor(origin string, msg *transport.Message) types.Rumor {
	r.Lock()
	defer r.Unlock()
	rumorList, _ := r.addOrGetOriginInternal(origin)
	seqNum := uint(len(rumorList.Rumors)) + 1

	rumor := types.Rumor{
		Origin:   origin,
		Sequence: seqNum,
		Msg:      msg,
	}
	rumorList.Rumors = append(rumorList.Rumors, rumor)
	if RumorManagerDebug {
		logr.Logger.Info().Msgf("[%s]: RumorManager state: %s\n", r.addr, r.PrintMe())
	}
	return rumor
}

func (r *RumorManager) getStatusMessageInternal() types.StatusMessage {
	result := make(map[string]uint)
	for origin, rumorList := range r.Items {
		if len(rumorList.Rumors) > 0 {
			result[origin] = rumorList.Rumors[len(rumorList.Rumors)-1].Sequence
		}
	}
	return result
}

func (r *RumorManager) GetStatuses() map[string][]uint {
	r.RLock()
	defer r.RUnlock()
	result := make(map[string][]uint)
	for origin, rumorList := range r.Items {
		if len(rumorList.Rumors) > 0 {
			result[origin] = make([]uint, len(rumorList.Rumors))
			for i, rumor := range rumorList.Rumors {
				result[origin][i] = rumor.Sequence
			}
		}
	}
	return result
}

func (r *RumorManager) GetStatusMessage() types.StatusMessage {
	r.RLock()
	defer r.RUnlock()
	return r.getStatusMessageInternal()
}

func (r *RumorManager) GetRumorsFromSeqMapInternal(seqMap map[string]uint) []types.Rumor {
	rumorsToSend := []types.Rumor{}
	for origin := range seqMap {
		rumorList, ok := r.addOrGetOriginInternal(origin)
		if !ok {
			// logr.Logger.Error().Msgf("[%s]: Could not find rumors for origin %s", r.addr, origin)
			continue
		}
		rumorsToSend = append(rumorsToSend, rumorList.Rumors[seqMap[origin]:]...)
	}
	sort.Slice(rumorsToSend, func(i, j int) bool {
		return rumorsToSend[i].Sequence < rumorsToSend[j].Sequence
	})
	return rumorsToSend
}

func (r *RumorManager) PrintMe() string {
	rumorsCopy := r.GetCopy()
	streng := ""
	for origin := range rumorsCopy {
		streng = streng + origin + ": " + fmt.Sprint(len(rumorsCopy[origin].Rumors)) + ", "
	}
	return streng
}

func (n *node) ProcessRumoursMessage(
	rumorsMessage *types.RumorsMessage,
	pkt transport.Packet,
) error {
	n.rumorManager.Lock()
	defer n.rumorManager.Unlock()
	foundExpected := false
	isMyOwnMessage := pkt.Header.Source == n.addr
	for _, rumor := range rumorsMessage.Rumors {
		ok := isMyOwnMessage || n.rumorManager.AddRumorInternal(rumor)
		if ok {
			if !isMyOwnMessage && !n.routingTable.IsNeighbour(rumor.Origin) {
				n.SetRoutingEntry(rumor.Origin, pkt.Header.RelayedBy)
			}
			newPkt := transport.Packet{
				Header: pkt.Header,
				Msg:    rumor.Msg,
			}
			foundExpected = true
			go func() {
				err := n.conf.MessageRegistry.ProcessPacket(newPkt)
				if err != nil {
					logr.Logger.Err(err).Msgf("[%s]: Error processing packet", n.addr)
				}
			}()
		}
	}
	go func() {
		err := n.sendAck(pkt)
		if err != nil {
			logr.Logger.Err(err).Msgf("[%s]: execRumorsMessage failed", n.addr)
		}
	}()

	forbiddenAddresses := peer.NewSet(pkt.Header.Source, pkt.Header.RelayedBy, n.addr)
	if foundExpected {
		logr.Logger.Trace().Msgf("[%s]: Sending status to random neighbour", n.addr)
		// Do not send to yourself or to source or to relay.
		// TO.DO: Not sure if we shouldnt send to relay. It's not in the spec.
		go func() {
			err := n.SendToRandomNeighbour(rumorsMessage, forbiddenAddresses, true)
			if err != nil {
				logr.Logger.Err(err).Msgf("[%s]: execRumorsMessage failed", n.addr)
			}
		}()
	}
	return nil
}

func (n *node) ProcessStatusMessage(
	incomingStatusMessage *types.StatusMessage,
	pkt transport.Packet,
) error {
	n.rumorManager.Lock()
	defer n.rumorManager.Unlock()
	myStatus := n.rumorManager.getStatusMessageInternal()
	neighborHasMessagesILack, seqNumsToSend := compareStatusMessages(
		myStatus,
		*incomingStatusMessage,
	)
	iHaveMessagesNeighborLacks := len(seqNumsToSend) > 0

	if neighborHasMessagesILack {
		// 1. The remote peer has Rumors that the peer P doesn’t have.
		// The peer P must send a status message to the remote peer.
		go func() {
			err := n.UnicastTypes(pkt.Header.Source, myStatus, true)
			if err != nil {
				logr.Logger.Err(err).
					Msgf("[%s]: Failed to send status message to %s", n.addr, pkt.Header.Source)
			}
		}()
	}
	if iHaveMessagesNeighborLacks {
		// 2. The peer P has Rumors that the remote peer doesn’t have.
		// The peer P must send all the missing Rumors, in order of increasing sequence number
		// and in a single RumorsMessage, to the remote peer.
		// logr.Logger.Info().
		// 	Msgf("[%s]: I have messages seqNums [%v] that the neighbor %s lacks", n.addr, seqNumsToSend, pkt.Header.Source)
		rumorsToSend := n.rumorManager.GetRumorsFromSeqMapInternal(seqNumsToSend)
		rumorsMessage := types.RumorsMessage{
			Rumors: rumorsToSend,
		}
		go func() {
			err := n.UnicastTypes(pkt.Header.Source, rumorsMessage, true)
			if err != nil {
				logr.Logger.Err(err).
					Msgf("[%s]: Failed to send lacking messages to %s", n.addr, pkt.Header.Source)
			}
		}()
	}

	// 4: Both peers have the same view. With a certain probability, peer P sends a status message to a random neighbor
	if !neighborHasMessagesILack && !iHaveMessagesNeighborLacks &&
		rand.Float64() < n.conf.ContinueMongering {
		go func() {
			err := n.SendToRandomNeighbour(myStatus, peer.NewSet(n.addr, pkt.Header.Source), true)
			if err != nil {
				logr.Logger.Err(err).
					Msgf("[%s]: Failed to send status message to random neighbour", n.addr)
			}
		}()
	}
	return nil
}
