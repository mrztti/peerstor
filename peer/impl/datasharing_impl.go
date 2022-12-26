package impl

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
)

// GetRoutingTable implements peer.Service
func (n *node) Upload(data io.Reader) (metahash string, err error) {
	chunkSize := n.conf.ChunkSize
	metafile := ""
	metahashBytes := crypto.SHA256.New()
	for {
		chunk := make([]byte, chunkSize)
		chunkLength, err := data.Read(chunk)
		if err != nil && err != io.EOF {
			logr.Logger.Err(err).Msgf("[%s]: Failed to read chunk", n.addr)
			return "", err
		}
		if chunkLength == 0 {
			break
		}
		chunk = chunk[:chunkLength]
		chunkHash, hexedChunkHash := createChunkHash(chunk)
		n.blobStore.Set(hexedChunkHash, chunk)
		if metafile != "" {
			metafile += peer.MetafileSep
		}
		metafile += hexedChunkHash
		metahashBytes.Write(chunkHash)
	}
	metahash = hex.EncodeToString(metahashBytes.Sum(nil))
	n.blobStore.Set(metahash, []byte(metafile))
	return metahash, nil
}

func (n *node) UpdateCatalog(key string, newPeer string) {
	n.catalog.UpdateCatalog(key, newPeer)
}

func (n *node) GetCatalog() peer.Catalog {
	return n.catalog.GetCatalog()
}

func (n *node) Download(metahash string) ([]byte, error) {
	metafile := n.blobStore.Get(metahash)
	if metafile == nil {
		randomPeerToAsk, err := n.catalog.GetRandomEntryFor(metahash)
		if err != nil {
			logr.Logger.Err(err).
				Msgf("[%s]: Failed to get random peer for metahash %s. No such peer present.", n.addr, metahash)
			return nil, err
		}
		metafile, err = n.downloadChunkFromPeer(metahash, randomPeerToAsk)
		if err != nil {
			logr.Logger.Err(err).
				Msgf("[%s]: Failed to download chunk from peer %s", n.addr, randomPeerToAsk)
			return nil, err
		}
		n.blobStore.Set(metahash, metafile)
	}
	chunks := parseMetafile(metafile)
	var data []byte
	for _, chunk := range chunks {
		chunkData := n.blobStore.Get(chunk)
		if chunkData == nil {
			randomPeerToAsk, err := n.catalog.GetRandomEntryFor(chunk)
			if err != nil {
				logr.Logger.Err(err).
					Msgf("[%s]: Failed to download chunk %s. No peer in catalogue", n.addr, chunk)
				return nil, err
			}
			chunkData, err = n.downloadChunkFromPeer(chunk, randomPeerToAsk)
			if err != nil {
				logr.Logger.Err(err).
					Msgf("[%s]: Failed to download chunk %s from peer %s", n.addr, chunk, randomPeerToAsk)
				return nil, err
			}
			n.blobStore.Set(chunk, chunkData)
		}
		data = append(data, chunkData...)
	}
	return data, nil
}

func (n *node) downloadChunkFromPeer(chunk, peer string) ([]byte, error) {
	if !n.routingTable.Has(peer) {
		err := fmt.Errorf("[%s]: peer not found", n.addr)
		logr.Logger.Err(err).
			Msgf("[%s]: Failed to download chunk %s from peer %s", n.addr, chunk, peer)
		return nil, err
	}
	requestID := xid.New().String()
	responseChannel := n.responseManager.CreateDataResponseChannel(requestID)
	err := n.sendDataRequest(requestID, peer, chunk, 0)
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Failed to send data request to peer %s", n.addr, peer)
		n.responseManager.StopDataRequestTimeout(requestID, true, false)
		return nil, err
	}
	chunkData := <-responseChannel
	if chunkData == nil {
		err := fmt.Errorf("[%s]: Failed to download chunk %s from peer %s", n.addr, chunk, peer)
		logr.Logger.Err(err).
			Msgf("[%s]: Failed to download chunk %s from peer %s", n.addr, chunk, peer)
		return nil, err
	}
	return *chunkData, nil
}

func (n *node) Tag(name string, mh string) error {
	// time.Sleep(time.Duration((rand.Intn(9))+1) * 100 * time.Millisecond)
	logr.Logger.Trace().Msgf("[%s]: Tagging function called: name: %s mh: %s. Step is: %d",
		n.addr, name, mh, n.paxos.currentStep.Get())
	defer logr.Logger.Trace().
		Msgf("[%s]: Tagging function finished with: name: %s mh: %s. Step is: %d",
			n.addr, name, mh, n.paxos.currentStep.Get())
	n.paxos.taggingLock.Lock()
	defer n.paxos.taggingLock.Unlock()
	if n.conf.TotalPeers <= 1 {
		n.namingStore.Set(name, []byte(mh))
		return nil
	}
	for {
		if n.namingStore.Get(name) != nil {
			return fmt.Errorf("name already exists")
		}
		if !n.paxos.skipNextResendTick.Get() {
			// time.Sleep(time.Duration((rand.Intn(9))+1) * 100 * time.Millisecond)
			phase1Propose := ProposePhase1Message{
				value: &types.PaxosValue{
					UniqID:   xid.New().String(),
					Filename: name,
					Metahash: mh,
				},
			}
			logr.Logger.Trace().
				Msgf("[%s]: Sending to inner channel: PROPOSER_PHASE_1_REQUEST with contents %#v", n.addr, phase1Propose)
			n.paxosInnerMessageChannel <- &phase1Propose
			logr.Logger.Trace().
				Msgf("[%s]: PROPOSER_PHASE_1_REQUEST has been read from the channel.", n.addr)
		}
		n.paxos.skipNextResendTick.Set(false)
		select {
		case consensusValue := <-n.paxos.consensusChannel:
			logr.Logger.Trace().
				Msgf("[%s]: Consensus reached for filename %s, mh %s. We proposed name %s, mh %s",
					n.addr, consensusValue.Filename, consensusValue.Metahash, name, mh)
			n.paxos.skipNextResendTick.Set(false)
			if consensusValue.Filename != name || consensusValue.Metahash != mh {
				logr.Logger.Trace().
					Msgf("[%s]: Consensus value is not our value, restarting. Current step is %d",
						n.addr, n.paxos.currentStep.Get())
				logr.Logger.Trace().Msgf("[%s]: Off to bed", n.addr)
				time.Sleep(1000 * time.Millisecond)
				logr.Logger.Trace().Msgf("[%s]: Awake", n.addr)
				continue
			}
			logr.Logger.Trace().
				Msgf("[%s]: Consensus value is our value, returning. Current step is %d",
					n.addr, n.paxos.currentStep.Get())
			return nil
		case <-time.After(n.conf.PaxosProposerRetry):
			logr.Logger.Trace().Msgf("[%s]: Timeout reached, restarting. Current step is %d",
				n.addr, n.paxos.currentStep.Get())
			continue
		}

	}
}

func (n *node) Resolve(name string) (metahash string) {
	mh := n.namingStore.Get(name)
	return string(mh)
}

func (n *node) SearchAll(
	reg regexp.Regexp,
	budget uint,
	timeout time.Duration,
) (names []string, err error) {
	myNames, _ := n.searchNamingStore(reg)
	namesSet := peer.NewSet(myNames...)
	namesMutex := sync.RWMutex{}
	requestID := xid.New().String()
	responseChannel := n.responseManager.CreateSearchAllChannel(requestID)
	err = n.sendSearchRequest(requestID, n.addr, budget, reg.String(), peer.NewSet(n.addr))
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Failed to send search request", n.addr)
		n.responseManager.searchAllChannelStore.Remove(requestID)
		return nil, err
	}
	for {
		select {
		case <-time.After(timeout):
			namesMutex.Lock()
			defer namesMutex.Unlock()
			n.responseManager.searchAllChannelStore.Remove(requestID)
			close(responseChannel)
			return namesSet.Values(), nil
		case moreNames := <-responseChannel:
			namesMutex.Lock()
			namesSet.Add(moreNames...)
			namesMutex.Unlock()
		}
	}

}

func (n *node) searchNamingStore(reg regexp.Regexp) (names []string, metahashes [][]byte) {
	names = make([]string, 0)
	metahashes = make([][]byte, 0)
	n.namingStore.ForEach(func(key string, value []byte) bool {
		if reg.MatchString(key) {
			names = append(names, key)
			metahashes = append(metahashes, value)
		}
		return true
	})
	logr.Logger.Info().
		Msgf("[%s]: Found %d entries in naming store for pattern %s: %s", n.addr, len(names), reg.String(), names)
	return names, metahashes
}

func (n *node) SearchFirst(
	pattern regexp.Regexp,
	conf peer.ExpandingRing,
) (name string, err error) {
	// Search locally
	names, metahashes := n.searchNamingStore(pattern)
	for i, name := range names {
		if n.fileFullyKnown(metahashes[i]) {
			return name, nil
		}
	}
	// Search remotely
	return n.searchFirstRemotely(pattern, conf, 0, conf.Initial)

}

func (n *node) searchFirstRemotely(
	reg regexp.Regexp,
	conf peer.ExpandingRing,
	retryCount uint,
	budget uint,
) (name string, err error) {
	if retryCount >= conf.Retry {
		return "", nil
	}
	requestID := xid.New().String()
	responseChannel := n.responseManager.CreateSearchFirstChannel(requestID)
	err = n.sendSearchRequest(requestID, n.addr, budget, reg.String(), peer.NewSet(n.addr))
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Failed to send search request", n.addr)
		n.responseManager.searchFirstChannelStore.Remove(requestID)
		return "", err
	}
	for {
		select {
		case <-time.After(conf.Timeout):
			n.responseManager.searchFirstChannelStore.Remove(requestID)
			close(responseChannel)
			return n.searchFirstRemotely(reg, conf, retryCount+1, budget*conf.Factor)
		case name := <-responseChannel:
			n.responseManager.searchFirstChannelStore.Remove(requestID)
			close(responseChannel)
			return name, nil
		}
	}

}

func (n *node) fileFullyKnown(metahash []byte) bool {
	metafile := n.blobStore.Get(string(metahash))
	chunkHashes := parseMetafile(metafile)
	return metafile != nil && n.allChunksInStore(chunkHashes)
}

func (n *node) allChunksInStore(chunkHashes []string) bool {
	for _, chunkHash := range chunkHashes {
		if n.blobStore.Get(chunkHash) == nil {
			return false
		}
	}
	return true
}
