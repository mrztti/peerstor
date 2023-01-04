package impl

import (
	"sync"

	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/storage"
	"go.dedis.ch/cs438/transport"
)

type PaxosMessage interface {
	Name() string
}

// NewPeer creates a new peer. You can change the content and location of this
// function but you MUST NOT change its signature and package location.
func NewPeer(conf peer.Configuration) peer.Peer {
	myAddr := conf.Socket.GetAddress()
	logr.Logger.Info().Msgf("[%s]: New peer", myAddr)

	// Generate certificate information
	certificateStore, err := GenerateCertificateStore(2048)
	if err != nil {
		logr.Logger.Error().Msgf("[%s]: Failed to generate certificate store", myAddr)
		return nil
	}

	newPeer := &node{
		conf:                     conf,
		quitChannel:              make(chan bool),
		routingTable:             CreateRoutingTable(myAddr),
		rumorManager:             CreateRumorManager(myAddr),
		addr:                     myAddr,
		responseManager:          CreateResponseManager(myAddr),
		blobStore:                conf.Storage.GetDataBlobStore(),
		namingStore:              conf.Storage.GetNamingStore(),
		catalog:                  CreateConcurrentCatalog(myAddr),
		paxos:                    CreateMultiPaxos(myAddr, conf, nil),
		paxosInnerMessageChannel: make(chan PaxosMessage),
		broadcastLock:            sync.Mutex{},
		attemptedRumoursSent:     &AtomicCounter{count: 0},
		certificateStore:         certificateStore,
	}
	newPeer.paxos.node = newPeer
	newPeer.routingTable.Set(myAddr, myAddr)
	newPeer.registerRegistryCallbacks()
	return newPeer
}

// node implements a peer to build a Peerster system
//
// - implements peer.Peer

type node struct {
	peer.Peer
	// You probably want to keep the peer.Configuration on this struct:
	conf                     peer.Configuration
	quitChannel              chan bool
	routingTable             RoutingTable
	rumorManager             RumorManager
	responseManager          ResponseManager
	addr                     string
	blobStore                storage.Store
	namingStore              storage.Store
	catalog                  ConcurrentCatalog
	paxos                    *MultiPaxos
	paxosInnerMessageChannel chan PaxosMessage
	broadcastLock            sync.Mutex
	attemptedRumoursSent     *AtomicCounter
	certificateStore         *CertificateStore
}

// Start implements peer.Service
func (n *node) Start() error {
	logr.Logger.Info().Msgf("[%s]: Starting peer", n.addr)
	myAddr := n.conf.Socket.GetAddress()
	n.routingTable.Set(myAddr, myAddr)
	go n.startListeningService()
	// go n.startTickingService()
	go n.startPaxosService()
	if n.conf.AntiEntropyInterval > 0 {
		go n.startAntiEntropyService()
	}
	if n.conf.HeartbeatInterval > 0 {
		go n.startHeartbeatService()
	}

	// Broadcast Node certificate
	n.BroadcastCertificate()
	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	close(n.quitChannel)
	return nil
}

// AddPeer implements peer.Service
func (n *node) AddPeer(addr ...string) {
	logr.Logger.Info().Msgf("[%s]: Adding peers %s", n.addr, n.addr)
	for _, ad := range addr {
		if ad == n.conf.Socket.GetAddress() || n.routingTable.Has(ad) {
			continue
		}
		n.routingTable.Set(ad, ad)
		n.rumorManager.AddOrGetOrigin(ad)
	}
}

// GetRoutingTable implements peer.Service
func (n *node) GetRoutingTable() peer.RoutingTable {
	return n.routingTable.GetCopy()
}

// SetRoutingEntry implements peer.Service
func (n *node) SetRoutingEntry(origin, relayAddr string) {
	if relayAddr == "" {
		n.routingTable.Remove(origin)
		return
	}
	n.routingTable.Set(origin, relayAddr)
}

func (n *node) handleIncomingPacket(pkt transport.Packet) {
	// logr.Logger.Trace().
	// 	Msgf("[%s]: Received packet %s (type %s) from %s headed for %s with payload %s",
	// 		n.addr, pkt.Header.PacketID, pkt.Msg.Type, pkt.Header.Source, pkt.Header.Destination, pkt.Msg.Payload)
	myAddr := n.conf.Socket.GetAddress()
	var err error
	if pkt.Header.Destination == myAddr {
		err = n.conf.MessageRegistry.ProcessPacket(pkt)
		if err != nil {
			logr.Logger.Err(err).Msgf("[%s]: Failed to process packet", n.addr)
		}
	} else {
		pkt.Header.RelayedBy = myAddr
		nextHop, _ := n.routingTable.Get(pkt.Header.Destination)
		err = n.socketSend(nextHop, pkt)
		if err != nil {
			logr.Logger.Err(err).Msgf("[%s]: Failed to send packet", n.addr)
		}
		return
	}
}
