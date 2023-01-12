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
	tlsManager := CreateTLSManager(myAddr)
	certificateStore, err := GenerateCertificateStore(2048)
	tlsManager.SetOwnKeys(certificateStore.GetPublicKey(), certificateStore.GetPrivateKey())
	if err != nil {
		logr.Logger.Error().Msgf("[%s]: Failed to generate certificate store", myAddr)
		return nil
	}
	newPeer := &node{
		conf:                        conf,
		quitChannel:                 make(chan bool),
		routingTable:                CreateRoutingTable(myAddr),
		rumorManager:                CreateRumorManager(myAddr),
		addr:                        myAddr,
		responseManager:             CreateResponseManager(myAddr),
		blobStore:                   conf.Storage.GetDataBlobStore(),
		namingStore:                 conf.Storage.GetNamingStore(),
		catalog:                     CreateConcurrentCatalog(myAddr),
		paxosInnerMessageChannel:    make(chan PaxosMessage),
		banPaxosInnerMessageChannel: make(chan PaxosMessage),
		broadcastLock:               sync.Mutex{},
		attemptedRumoursSent:        &AtomicCounter{count: 0},
		certificateStore:            certificateStore,
		certificateVerifications:    peer.CreateConcurrentMap[chan []byte](),
		trustBanHook:                make(chan string),
		isOnionNode:                 false,
		tlsManager:                  tlsManager,
		torManager:                  CreateTorManager(myAddr),
		isMalicious:                 false,
	}
	// Init blockchains
	newPeer.paxos = CreateMultiPaxos(conf, newPeer, conf.Storage.GetBlockchainStore())
	newPeer.banPaxos = CreateMultiPaxos(conf, newPeer, conf.Storage.GetBanBlockchainStore())

	newPeer.routingTable.Set(myAddr, myAddr)
	newPeer.registerRegistryCallbacks()
	err = newPeer.NewTrustCatalog(0.5)
	if err != nil {
		logr.Logger.Error().Msgf("[%s]: Failed to create trust catalog", myAddr)
		return nil
	}
	err = newPeer.NewNodeCatalog()
	if err != nil {
		logr.Logger.Error().Msgf("[%s]: Failed to create node catalog", myAddr)
		return nil
	}
	err = newPeer.NewCertificateCatalog()
	if err != nil {
		logr.Logger.Error().Msgf("[%s]: Failed to create certificate catalog", myAddr)
		return nil
	}

	return newPeer
}

// node implements a peer to build a Peerster system
//
// - implements peer.Peer

type node struct {
	peer.Peer
	// You probably want to keep the peer.Configuration on this struct:
	conf                        peer.Configuration
	quitChannel                 chan bool
	routingTable                RoutingTable
	rumorManager                RumorManager
	responseManager             ResponseManager
	addr                        string
	blobStore                   storage.Store
	namingStore                 storage.Store
	catalog                     ConcurrentCatalog
	paxos                       *MultiPaxos
	paxosInnerMessageChannel    chan PaxosMessage
	banPaxosInnerMessageChannel chan PaxosMessage
	broadcastLock               sync.Mutex
	attemptedRumoursSent        *AtomicCounter
	certificateStore            *CertificateStore
	certificateCatalog          *CertificateCatalog
	certificateVerifications    peer.ConcurrentMap[chan []byte]
	trustCatalog                *TrustCatalog
	trustBanHook                chan string
	banPaxos                    *MultiPaxos
	nodeCatalog                 *NodeCatalog
	isOnionNode                 bool
	tlsManager                  *TLSManager
	torManager                  *TorManager
	isMalicious                 bool
}

// Start implements peer.Service
func (n *node) Start() error {
	logr.Logger.Info().Msgf("[%s]: Starting peer", n.addr)
	myAddr := n.conf.Socket.GetAddress()
	n.routingTable.Set(myAddr, myAddr)

	// For testing purposes
	if n.conf.PrivateKey != nil && n.conf.PublicKey != nil {
		n.tlsManager.SetOwnKeys(n.conf.PublicKey, n.conf.PrivateKey)
	}

	go n.startListeningService()
	// go n.startTickingService()
	go n.startPaxosService()
	go n.startBanPaxosService()
	go n.startBanService()
	if n.conf.AntiEntropyInterval > 0 {
		go n.startAntiEntropyService()
	}
	if n.conf.HeartbeatInterval > 0 {
		go n.startHeartbeatService()
	}

	// Broadcast Node certificate
	err := n.BroadcastCertificate()
	if err != nil {
		logr.Logger.Error().Msgf("[%s]: Failed to broadcast certificate", n.addr)
	}

	if n.conf.IsOnionNode {
		err := n.RegisterAsOnionNode()
		if err != nil {
			logr.Logger.Error().Msgf("[%s]: Failed to add our node as onion", myAddr)
			return err
		}
	}

	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	// Check if already closed
	n.quitChannel <- true
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
