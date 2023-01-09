package impl

import (
	"errors"
	"time"

	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) startListeningService() {
	sock := n.conf.Socket
	myAddr := sock.GetAddress()
	for {
		select {
		case <-n.quitChannel:
			logr.Logger.Info().Msgf("[%s]: Node quitting", myAddr)
			return
		default:
			pkt, err := sock.Recv(time.Second * 1)
			if errors.Is(err, transport.TimeoutError(0)) {
				continue
			}
			if err != nil {
				logr.Logger.Err(err).Msg("Failed to receive packet")
			}
			n.handleIncomingPacket(pkt)
		}
	}
}

// func (n *node) startTickingService() {
// 	ticker := time.NewTicker(1 * time.Second)
// 	for {
// 		select {
// 		case <-ticker.C:
// 			statuses := n.rumorManager.GetStatuses()
// 			lenghts := ""
// 			for origin, status := range statuses {
// 				lenghts += origin + ":" + fmt.Sprint(len(status)) + " "
// 			}

// 			logr.Logger.Trace().Msgf("[%s]: I tried sending: %d rumours. Received: %s. My complete status is: %#v.",
// 				n.addr, n.attemptedRumoursSent.Get(), lenghts, statuses)
// 		case <-n.quitChannel:
// 			ticker.Stop()
// 			return
// 		}
// 	}

// }

func (n *node) startAntiEntropyService() {
	myAddr := n.conf.Socket.GetAddress()
	ticker := time.NewTicker(n.conf.AntiEntropyInterval)
	forbiddenAddresses := peer.NewSet(myAddr)
	for {
		select {
		case <-ticker.C:
			// TO.DO: Again here is a mismatch between the copy and the sending
			// we might be sending an out-of-date copy of the sequence table.
			// Hopefully this should not be a big deal though.
			statusMessage := n.rumorManager.GetStatusMessage()
			err := n.SendToRandomNeighbour(statusMessage, forbiddenAddresses, true)
			if err != nil {
				logr.Logger.Err(err).Msgf("[%s]: Failed to send status message", n.addr)
			}
		case <-n.quitChannel:
			ticker.Stop()
			return
		}
	}
}

func (n *node) startHeartbeatService() {
	ticker := time.NewTicker(n.conf.HeartbeatInterval)
	getEmptyMessage := func() transport.Message {
		emptyMessage, err := n.conf.MessageRegistry.MarshalMessage(types.EmptyMessage{})
		if err != nil {
			logr.Logger.Err(err).Msg("Failed to marshal empty message for heartbeat")
		}
		return emptyMessage
	}
	err := n.Broadcast(getEmptyMessage())
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Failed to send heartbeat", n.addr)
	}
	for {
		select {
		case <-ticker.C:
			err = n.Broadcast(getEmptyMessage())
			if err != nil {
				logr.Logger.Err(err).Msgf("[%s]: Failed to send heartbeat", n.addr)
			}
		case <-n.quitChannel:
			ticker.Stop()
			return
		}
	}
}

var PrepareMessageName = (types.PaxosPrepareMessage{}).Name()
var PromiseMessageName = (types.PaxosPromiseMessage{}).Name()
var ProposeMessageName = (types.PaxosProposeMessage{}).Name()
var AcceptMessageName = (types.PaxosAcceptMessage{}).Name()
var TLCMessageName = (types.TLCMessage{}).Name()
var ProposePhase1MessageName = (ProposePhase1Message{}).Name()

func (n *node) startPaxosService() {
	for {
		select {
		case message := <-n.paxosInnerMessageChannel:
			switch messageName := (message).Name(); messageName {
			case PrepareMessageName:
				paxosPrepare, _ := message.(*types.PaxosPrepareMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for paxosPrepare: %#v", n.addr, paxosPrepare)
				n.handlePrepareMessage(paxosPrepare)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for paxosPrepare: %#v",
						n.addr, paxosPrepare)
			case PromiseMessageName:
				paxosPromise, _ := message.(*types.PaxosPromiseMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for paxosPromise: %#v", n.addr, paxosPromise)
				n.handlePromiseMessage(paxosPromise)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for paxosPromise: %#v",
						n.addr, paxosPromise)
			case ProposeMessageName:
				paxosPropose, _ := message.(*types.PaxosProposeMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for paxosPropose: %#v", n.addr, paxosPropose)
				n.handleProposeMessage(paxosPropose)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for paxosPropose: %#v",
						n.addr, paxosPropose)
			case AcceptMessageName:
				paxosAccept, _ := message.(*types.PaxosAcceptMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for paxosAccept: %#v", n.addr, paxosAccept)
				n.handleAcceptMessage(paxosAccept)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for paxosAccept: %#v",
						n.addr, paxosAccept)
			case TLCMessageName:
				tlcMessage, _ := message.(*types.TLCMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for tlcMessage: %#v", n.addr, tlcMessage)
				n.handleTLCMessage(tlcMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for tlcMessage: %#v",
						n.addr, tlcMessage)
			case ProposePhase1MessageName:
				proposePhase1Message, _ := message.(*ProposePhase1Message)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for proposePhase1Request: %#v", n.addr, proposePhase1Message)
				n.handleProposePhase1Message(proposePhase1Message)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for proposePhase1Request: %#v",
						n.addr, proposePhase1Message)
			default:
				logr.Logger.Fatal().Msgf("[%s]: Unknown message type %s", n.addr, messageName)
			}
		case <-n.quitChannel:
			return
		}
	}
}

var BanPrepareMessageName = (types.BanPaxosPrepareMessage{}).Name()
var BanPromiseMessageName = (types.BanPaxosPromiseMessage{}).Name()
var BanProposeMessageName = (types.BanPaxosProposeMessage{}).Name()
var BanAcceptMessageName = (types.BanPaxosAcceptMessage{}).Name()
var BanTLCMessageName = (types.BanTLCMessage{}).Name()
var BanProposePhase1MessageName = (BanProposePhase1Message{}).Name()

func (n *node) startBanPaxosService() {
	for {
		select {
		case message := <-n.banPaxosInnerMessageChannel:
			switch messageName := (message).Name(); messageName {
			case BanPrepareMessageName:
				paxosPrepare, _ := message.(*types.BanPaxosPrepareMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for paxosPrepare: %#v", n.addr, paxosPrepare)
				n.handleBanPrepareMessage(paxosPrepare)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for ban_paxosPrepare: %#v",
						n.addr, paxosPrepare)
			case BanPromiseMessageName:
				paxosPromise, _ := message.(*types.BanPaxosPromiseMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for paxosPromise: %#v", n.addr, paxosPromise)
				n.handleBanPromiseMessage(paxosPromise)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for ban_paxosPromise: %#v",
						n.addr, paxosPromise)
			case BanProposeMessageName:
				paxosPropose, _ := message.(*types.BanPaxosProposeMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for paxosPropose: %#v", n.addr, paxosPropose)
				n.handleBanProposeMessage(paxosPropose)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for ban_paxosPropose: %#v",
						n.addr, paxosPropose)
			case BanAcceptMessageName:
				paxosAccept, _ := message.(*types.BanPaxosAcceptMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for paxosAccept: %#v", n.addr, paxosAccept)
				n.handleBanAcceptMessage(paxosAccept)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for ban_paxosAccept: %#v",
						n.addr, paxosAccept)
			case BanTLCMessageName:
				tlcMessage, _ := message.(*types.BanTLCMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for tlcMessage: %#v", n.addr, tlcMessage)
				n.handleBanTLCMessage(tlcMessage)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for ban_tlcMessage: %#v",
						n.addr, tlcMessage)
			case BanProposePhase1MessageName:
				proposePhase1Message, _ := message.(*BanProposePhase1Message)
				logr.Logger.Trace().
					Msgf("[%s]: Calling handler for proposePhase1Request: %#v", n.addr, proposePhase1Message)
				n.handleBanProposePhase1Message(proposePhase1Message)
				logr.Logger.Trace().
					Msgf("[%s]: Ready for next message. Finished handler for ban_proposePhase1Request: %#v",
						n.addr, proposePhase1Message)
			default:
				logr.Logger.Fatal().Msgf("[%s]: Unknown message type %s", n.addr, messageName)
			}
		case <-n.quitChannel:
			return
		}
	}
}
