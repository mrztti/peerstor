package impl

import (
	"math"
	"time"

	"github.com/pkg/errors"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
)

type ResponseManager struct {
	ackStore                 peer.ConcurrentMap[*time.Ticker]
	dataReqStore             peer.ConcurrentMap[*time.Ticker]
	dataResponseChannelStore peer.ConcurrentMap[chan *[]byte]
	searchAllChannelStore    peer.ConcurrentMap[chan []string]
	searchFirstChannelStore  peer.ConcurrentMap[chan string]
	seenSearchRequests       peer.ConcurrentSet[string]
	addr                     string
}

func CreateResponseManager(addr string) ResponseManager {
	return ResponseManager{
		ackStore:                 peer.CreateConcurrentMap[*time.Ticker](),
		dataReqStore:             peer.CreateConcurrentMap[*time.Ticker](),
		dataResponseChannelStore: peer.CreateConcurrentMap[chan *[]byte](),
		searchAllChannelStore:    peer.CreateConcurrentMap[chan []string](),
		searchFirstChannelStore:  peer.CreateConcurrentMap[chan string](),
		seenSearchRequests:       peer.CreateConcurrentSet[string](),
		addr:                     addr,
	}
}

func (r *ResponseManager) StartAckTimeout(
	ackID, currentDest string,
	msg *transport.Message,
	timeout time.Duration,
	n *node,
) {
	r.ackStore.Lock()
	defer r.ackStore.Unlock()
	existingTimeout, ok := r.ackStore.Items[ackID]
	if ok {
		logr.Logger.Error().
			Msgf("[%s]: ResponseManager: ackID %s already exists, stopping it", r.addr, ackID)
		existingTimeout.Stop()
	}
	ticker := time.NewTicker(timeout)
	r.ackStore.Items[ackID] = ticker
	go func() {
		for {
			select {
			case <-ticker.C:
				ticker.Stop()
				r.ackStore.Remove(ackID)
				forbiddenAddresses := peer.NewSet(n.addr, currentDest)
				err := n.SendToRandomNeighbourTransport(*msg, forbiddenAddresses, true)
				if err != nil {
					logr.Logger.Err(err).
						Msgf("[%s]: ResponseManager: failed to send message to random neighbour", r.addr)
				}
				return
			case <-n.quitChannel:
				ticker.Stop()
				r.ackStore.Remove(ackID)
				return
			}
		}
	}()
}

func (r *ResponseManager) StopAckTimeout(ackID string) {
	r.ackStore.Lock()
	defer r.ackStore.Unlock()
	ticker, ok := r.ackStore.Items[ackID]
	if !ok {
		//logr.Logger.Error().Msgf("[%s]: ResponseManager: ackID %s does not exist", r.addr, ackID)
		return
	}
	ticker.Stop()
	delete(r.ackStore.Items, ackID)
}

func (r *ResponseManager) CreateDataResponseChannel(requestID string) chan *[]byte {
	channel := make(chan *[]byte)
	r.dataResponseChannelStore.Set(requestID, channel)
	return channel
}

func (r *ResponseManager) StartDataRequestTimeout(
	requestID, dest, chunk string,
	currentIteration uint,
	n *node,
) {
	if r.dataReqStore.Has(requestID) {
		logr.Logger.Error().
			Msgf("[%s]: ResponseManager: ackID %s already exists", r.addr, requestID)
	}
	if currentIteration > n.conf.BackoffDataRequest.Retry {
		logr.Logger.Info().
			Msgf("[%s]: ResponseManager: currentIteration %d exceeds max retrainsmission count %d. Aborting.",
				r.addr, currentIteration, n.conf.BackoffDataRequest.Retry)
		r.ResolveResponse(requestID, nil)
	}
	backoffFactor :=
		math.Pow(float64(n.conf.BackoffDataRequest.Factor), float64(currentIteration))
	timeout := n.conf.BackoffDataRequest.Initial * time.Duration(backoffFactor)
	ticker := time.NewTicker(timeout)
	go func() {
		for {
			select {
			case <-ticker.C:
				ticker.Stop()
				r.dataReqStore.Remove(requestID)
				nextIteration := currentIteration + 1
				err := n.sendDataRequest(requestID, dest, chunk, nextIteration)
				if err != nil {
					logr.Logger.Err(err).
						Msgf("[%s]: ResponseManager: failed to send message to random neighbour", r.addr)
				}
				r.StartDataRequestTimeout(requestID, dest, chunk, nextIteration, n)
			case <-n.quitChannel:
				r.StopDataRequestTimeout(requestID, true, true)
				return
			}
		}
	}()
	r.dataReqStore.Set(requestID, ticker)
}

func (r *ResponseManager) StopDataRequestTimeout(
	requestID string,
	ignoreReqStore, ignoreDataStore bool,
) {
	ticker, ok := r.dataReqStore.Get(requestID)
	if !ok && !ignoreReqStore {
		logr.Logger.Error().
			Stack().
			Err(errors.New("requestID does not exist")).
			Msgf("[%s]: ResponseManager: requestID %s does not exist", r.addr, requestID)
	} else if ok {
		r.dataReqStore.Lock()
		ticker.Stop()
		r.dataReqStore.Unlock()
		r.dataReqStore.Remove(requestID)
	}
	channel, ok := r.dataResponseChannelStore.Get(requestID)
	if !ok && !ignoreDataStore {
		logr.Logger.Error().
			Msgf("[%s]: ResponseManager: requestID %s does not exist", r.addr, requestID)
	} else if ok {
		r.dataResponseChannelStore.Lock()
		close(channel)
		r.dataResponseChannelStore.Unlock()
		r.dataResponseChannelStore.Remove(requestID)
	}
}

func (r *ResponseManager) ResolveResponse(requestID string, dataReply []byte) {
	channel, ok := r.dataResponseChannelStore.Get(requestID)
	if !ok {
		logr.Logger.Info().
			Msgf("[%s]: ResponseManager: Trying to resolve data response but requestID %s does not exist", r.addr, requestID)
	} else {
		defer func() {
			if err := recover(); err != nil {
				logr.Logger.Error().
					Msgf("[%s](%s): ResponseManager: Trying to resolve data response but channel was closed, %#v",
						r.addr, requestID, err)
			}
		}()
		r.dataResponseChannelStore.Lock()
		channel <- &dataReply
		r.dataResponseChannelStore.Unlock()
	}
	r.StopDataRequestTimeout(requestID, false, false)
}

func (r *ResponseManager) CreateSearchAllChannel(requestID string) chan []string {
	channel := make(chan []string)
	r.searchAllChannelStore.Set(requestID, channel)
	return channel
}

func (r *ResponseManager) CreateSearchFirstChannel(requestID string) chan string {
	channel := make(chan string)
	r.searchFirstChannelStore.Set(requestID, channel)
	return channel
}
