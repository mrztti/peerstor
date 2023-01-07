package impl

import (
	"fmt"
	"regexp"

	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) registerRegistryCallbacks() {
	n.conf.MessageRegistry.RegisterMessageCallback(types.ChatMessage{}, n.execChatMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.RumorsMessage{}, n.execRumorsMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.StatusMessage{}, n.execStatusMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.AckMessage{}, n.execAckMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.EmptyMessage{}, n.execEmptyMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.PrivateMessage{}, n.execPrivateMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.DataReplyMessage{}, n.execDataReplyMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(
		types.DataRequestMessage{},
		n.execDataRequestMessage,
	)
	n.conf.MessageRegistry.RegisterMessageCallback(
		types.SearchRequestMessage{},
		n.execSearchRequestMessage,
	)
	n.conf.MessageRegistry.RegisterMessageCallback(
		types.SearchReplyMessage{},
		n.execSearchReplyMessage,
	)
	n.conf.MessageRegistry.RegisterMessageCallback(
		types.PaxosPrepareMessage{},
		n.execPaxosPrepareMessage,
	)
	n.conf.MessageRegistry.RegisterMessageCallback(
		types.PaxosPromiseMessage{},
		n.execPaxosPromiseMessage,
	)
	n.conf.MessageRegistry.RegisterMessageCallback(
		types.PaxosProposeMessage{},
		n.execPaxosProposeMessage,
	)
	n.conf.MessageRegistry.RegisterMessageCallback(
		types.PaxosAcceptMessage{},
		n.execPaxosAcceptMessage,
	)
	n.conf.MessageRegistry.RegisterMessageCallback(
		types.TLCMessage{},
		n.execTLCMessage,
	)
	n.conf.MessageRegistry.RegisterMessageCallback(
		CertificateBroadcastMessage{},
		n.HandleCertificateBroadcastMessage,
	)
	n.conf.MessageRegistry.RegisterMessageCallback(
		OnionNodeRegistrationMessage{},
		n.HandleOnionNodeRegistrationMessage,
	)
	n.conf.MessageRegistry.RegisterMessageCallback(types.TLCMessage{}, n.execTLCMessage)
	// TLS Messages
	n.conf.MessageRegistry.RegisterMessageCallback(types.TLSMessage{}, n.execTLSMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.TLSMessageHello{}, n.execTLSMessageHello)
	n.conf.MessageRegistry.RegisterMessageCallback(types.TLSClientHello{}, n.execTLSClientHello)
	n.conf.MessageRegistry.RegisterMessageCallback(types.TLSServerHello{}, n.execTLSServerHello)

}

func (n *node) execChatMessage(msg types.Message, pkt transport.Packet) error {
	chatMsg, ok := msg.(*types.ChatMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: execChatMessage failed", n.addr)
		return localErr
	}
	logr.Logger.Info().Msg(chatMsg.Message)
	return nil
}

func (n *node) execRumorsMessage(msg types.Message, pkt transport.Packet) error {
	rumorsMessage, ok := msg.(*types.RumorsMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: fexecRumorsMessage ailed", n.addr)
		return localErr
	}
	err := n.ProcessRumoursMessage(rumorsMessage, pkt)
	return err
}

func (n *node) execStatusMessage(msg types.Message, pkt transport.Packet) error {
	incomingStatusMessage, ok := msg.(*types.StatusMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: fexecStatusMessage ailed", n.addr)
		return localErr
	}
	err := n.ProcessStatusMessage(incomingStatusMessage, pkt)
	return err
}

func (n *node) execAckMessage(msg types.Message, pkt transport.Packet) error {
	ackMessage, ok := msg.(*types.AckMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: execAckMessage failed", n.addr)
		return localErr
	}
	n.responseManager.StopAckTimeout(ackMessage.AckedPacketID)
	transportMessage, err := n.conf.MessageRegistry.MarshalMessage(ackMessage.Status)
	if err != nil {
		return err
	}
	err = n.conf.MessageRegistry.ProcessPacket(transport.Packet{
		Header: pkt.Header,
		Msg:    &transportMessage,
	})

	return err
}

func (n *node) execEmptyMessage(msg types.Message, pkt transport.Packet) error {
	_, ok := msg.(*types.EmptyMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: execEmptyMessage failed", n.addr)
		return localErr
	}
	logr.Logger.Info().
		Msgf("[%s]: Sending to inner channel: empty message from %s", n.addr, pkt.Header.Source)
	return nil
}

func (n *node) execPrivateMessage(msg types.Message, pkt transport.Packet) error {
	privateMessage, ok := msg.(*types.PrivateMessage)
	var err error
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: msg failed", n.addr)
		return localErr
	}
	_, ok = privateMessage.Recipients[n.addr]
	if ok {
		logr.Logger.Info().
			Msgf("[%s]: Processing private message from %s. Recipients were %#v",
				n.addr, pkt.Header.Source, privateMessage.Recipients)
		err = n.conf.MessageRegistry.ProcessPacket(transport.Packet{
			Header: pkt.Header,
			Msg:    privateMessage.Msg,
		})
	} else {
		logr.Logger.Info().Msgf("[%s]: Ignoring private message from %s. Recipients were %#v",
			n.addr, pkt.Header.Source, privateMessage.Recipients)
	}
	return err
}

func (n *node) execDataReplyMessage(msg types.Message, pkt transport.Packet) error {
	dataReply, ok := msg.(*types.DataReplyMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: faiexecDataReplyMessage led", n.addr)
		return localErr
	}
	n.responseManager.ResolveResponse(dataReply.RequestID, dataReply.Value)
	return nil
}

func (n *node) execDataRequestMessage(msg types.Message, pkt transport.Packet) error {
	dataRequest, ok := msg.(*types.DataRequestMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: faiexecDataRequestMessage led", n.addr)
		return localErr
	}
	chunkData := n.blobStore.Get(dataRequest.Key)
	if chunkData == nil {
		logr.Logger.Info().
			Msgf("[%s]: Wrong entry in catalogue: request to %s for %s got no data", n.addr, pkt.Header.Source, dataRequest.Key)
		err := n.catalog.RemoveEntryFor(dataRequest.Key, pkt.Header.Source)
		if err != nil {
			logr.Logger.Err(err).
				Msgf("[%s]: Failed to remove entry for %s from catalogue", n.addr, dataRequest.Key)
		}
	}
	return n.sendDataReply(dataRequest.RequestID, pkt.Header.Source, dataRequest.Key, chunkData)
}

func (n *node) execSearchRequestMessage(msg types.Message, pkt transport.Packet) error {
	searchRequest, ok := msg.(*types.SearchRequestMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: execSearchRequestMessage  failed", n.addr)
		return localErr
	}
	logr.Logger.Info().
		Msgf("[%s]: Budget is %d. Processing search request %s from %s", n.addr,
			searchRequest.Budget, searchRequest.RequestID, pkt.Header.Source)
	if n.responseManager.seenSearchRequests.Has(searchRequest.RequestID) {
		logr.Logger.Info().
			Msgf("[%s]: Ignoring duplicate search request %s from %s", n.addr, searchRequest.RequestID, pkt.Header.Source)
		return nil
	}
	n.responseManager.seenSearchRequests.Add(searchRequest.RequestID)
	if searchRequest.Budget > 1 {
		// Forward message if budget allows
		budget := searchRequest.Budget - 1
		err := n.sendSearchRequest(
			searchRequest.RequestID,
			searchRequest.Origin,
			budget,
			searchRequest.Pattern,
			peer.NewSet(n.addr, pkt.Header.Source),
		)
		if err != nil {
			logr.Logger.Err(err).
				Msgf("[%s]: Failed to forward search request %s", n.addr, searchRequest.RequestID)
		}
	}
	names, metahashes := n.searchNamingStore(*regexp.MustCompile(searchRequest.Pattern))
	fileInfos := make([]types.FileInfo, 0)
	n.blobStore.ForEach(func(key string, value []byte) bool {
		logr.Logger.Info().Msgf("[%s]: Blobstore has %s -> %s", n.addr, key, value)
		return true
	})
	for index, name := range names {
		metafile := n.blobStore.Get(string(metahashes[index]))
		logr.Logger.Info().
			Msgf("[%s]: Want to send metafile for name %s (index %d) and found %s. Blobstore has %d entries",
				n.addr, name, index, metafile, n.blobStore.Len())
		if metafile != nil {
			chunks := make([][]byte, 0)
			chunksHashes := parseMetafile(metafile)
			logr.Logger.Info().
				Msgf("[%s]: Want to send chunks %s for name %s (index %d)", n.addr, chunksHashes, name, index)
			for _, chunkHash := range chunksHashes {
				newChunks := n.blobStore.Get(chunkHash)
				logr.Logger.Info().
					Msgf("[%s]: Sending chunkhash %s for name %s (index %d). Found %s in blobstore",
						n.addr, chunkHash, name, index, newChunks)
				// Add the chunkHash but only if we have its corresponding contents
				if newChunks == nil {
					chunks = append(chunks, nil)
				} else {
					chunks = append(chunks, []byte(chunkHash))
				}

			}
			logr.Logger.Info().
				Msgf("[%s]: Sending %d chunks for name %s to [%s] via %s. Chunks: %#v",
					n.addr, len(chunks), name, searchRequest.Origin, pkt.Header.Source, chunks)
			fileInfo := types.FileInfo{
				Name:     name,
				Metahash: string(metahashes[index]),
				Chunks:   chunks,
			}
			fileInfos = append(fileInfos, fileInfo)
		}
	}
	err := n.sendSearchAllReply(
		searchRequest.RequestID,
		searchRequest.Origin,
		pkt.Header.Source,
		fileInfos,
	)
	if err != nil {
		logr.Logger.Err(err).
			Msgf("[%s]: Error sending search reply to %s via %s", n.addr, searchRequest.Origin, pkt.Header.Source)
	}
	return err
}

func (n *node) execSearchReplyMessage(msg types.Message, pkt transport.Packet) (err error) {
	searchReply, ok := msg.(*types.SearchReplyMessage)
	searchAllStore := &n.responseManager.searchAllChannelStore
	searchFirstStore := &n.responseManager.searchFirstChannelStore
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: localErr failed", n.addr)
		return localErr
	}
	logr.Logger.Info().
		Msgf("[%s](%s): Received search reply from %s with %d responses",
			n.addr, searchReply.RequestID, pkt.Header.Source, len(searchReply.Responses))
	names := make([]string, 0)
	totalMatches := make([]string, 0)
	for _, fileInfo := range searchReply.Responses {
		isTotalMatch := true
		names = append(names, fileInfo.Name)
		n.namingStore.Set(fileInfo.Name, []byte(fileInfo.Metahash))
		n.catalog.UpdateCatalog(fileInfo.Metahash, pkt.Header.Source)
		for _, chunkHash := range fileInfo.Chunks {
			if chunkHash != nil {
				n.catalog.UpdateCatalog(string(chunkHash), pkt.Header.Source)
			} else {
				isTotalMatch = false
			}
		}
		if isTotalMatch {
			totalMatches = append(totalMatches, fileInfo.Name)
		}
	}
	logr.Logger.Info().
		Msgf("[%s](%s): Processed search reply from %s with %d responses: %#v",
			n.addr, searchReply.RequestID, pkt.Header.Source, len(searchReply.Responses), names)
	maybeAllChannel, searchAllOk := searchAllStore.Get(searchReply.RequestID)
	if searchAllOk {
		logr.Logger.Info().
			Msgf("[%s]: Sending searchAll reply to channel %s", n.addr, searchReply.RequestID)
		searchAllStore.Lock()
		maybeAllChannel <- names
		searchAllStore.Unlock()
	}
	maybeFirstChannel, searchFirstOk := searchFirstStore.Get(searchReply.RequestID)
	if searchFirstOk && len(totalMatches) > 0 {
		logr.Logger.Info().
			Msgf("[%s]: Send searchFirst reply to channel %s", n.addr, searchReply.RequestID)
		searchAllStore.Lock()
		maybeFirstChannel <- totalMatches[0]
		searchAllStore.Unlock()
	}
	return err

}

func (n *node) execPaxosPrepareMessage(msg types.Message, pkt transport.Packet) error {
	paxosPrepare, ok := msg.(*types.PaxosPrepareMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: execPaxosPrepareMessage failed", n.addr)
		return localErr
	}
	go func() {
		logr.Logger.Trace().
			Msgf("[%s]: Sending to inner channel: paxosPrepare from %s with contents %#v",
				n.addr, pkt.Header.Source, paxosPrepare)
		n.paxosInnerMessageChannel <- paxosPrepare
		logr.Logger.Trace().
			Msgf("[%s]: paxosPrepare from %s has been read from the channel.", n.addr, pkt.Header.Source)
	}()
	return nil
}

func (n *node) execPaxosProposeMessage(msg types.Message, pkt transport.Packet) error {
	paxosPropose, ok := msg.(*types.PaxosProposeMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: execPaxosProposeMessage failed", n.addr)
		return localErr
	}
	go func() {
		logr.Logger.Trace().
			Msgf("[%s]: Sending to inner channel: paxosPropose from %s with contents %#v",
				n.addr, pkt.Header.Source, paxosPropose)
		n.paxosInnerMessageChannel <- paxosPropose
		logr.Logger.Trace().
			Msgf("[%s]: paxosPropose from %s has been read from the channel.", n.addr, pkt.Header.Source)
	}()
	return nil
}

func (n *node) execPaxosPromiseMessage(msg types.Message, pkt transport.Packet) error {
	paxosPromise, ok := msg.(*types.PaxosPromiseMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: execPaxosPromiseMessage failed", n.addr)
		return localErr
	}
	go func() {
		logr.Logger.Trace().
			Msgf("[%s]: Sending to inner channel: paxosPromise from %s with contents %#v",
				n.addr, pkt.Header.Source, paxosPromise)
		n.paxosInnerMessageChannel <- paxosPromise
		logr.Logger.Trace().
			Msgf("[%s]: paxosPromise from %s has been read from the channel.", n.addr, pkt.Header.Source)
	}()
	return nil
}

func (n *node) execPaxosAcceptMessage(msg types.Message, pkt transport.Packet) error {
	paxosAccept, ok := msg.(*types.PaxosAcceptMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: faiexecPaxosAcceptMessage led", n.addr)
		return localErr
	}
	go func() {
		logr.Logger.Trace().
			Msgf("[%s]: Sending to inner channel: paxosAccept from %s with contents %#v",
				n.addr, pkt.Header.Source, paxosAccept)
		n.paxosInnerMessageChannel <- paxosAccept
		logr.Logger.Trace().
			Msgf("[%s]: paxosAccept from %s has been read from the channel.", n.addr, pkt.Header.Source)
	}()
	return nil
}

func (n *node) execTLCMessage(msg types.Message, pkt transport.Packet) error {
	TLC, ok := msg.(*types.TLCMessage)
	if !ok {
		localErr := fmt.Errorf("wrong type: %T", msg)
		logr.Logger.Err(localErr).Msgf("[%s]: execTLCMessage failed", n.addr)
		return localErr
	}
	go func() {
		logr.Logger.Trace().
			Msgf("[%s]: Sending to inner channel: TLC from %s with contents %#v", n.addr, pkt.Header.Source, TLC)
		n.paxosInnerMessageChannel <- TLC
		logr.Logger.Trace().
			Msgf("[%s]: TLC from %s has been read from the channel.", n.addr, pkt.Header.Source)
	}()
	return nil
}
