package controller

import (
	"net/http"

	"github.com/rs/zerolog"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
)

func NewTor(node peer.Peer, log *zerolog.Logger) tor {
	return tor{
		node: node,
		log:  log,
	}
}

type tor struct {
	node peer.Peer
	log  *zerolog.Logger
}

func (t tor) TorHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			return
		default:
			http.Error(w, "forbidden method", http.StatusMethodNotAllowed)
			return
		}
	}
}

func (t tor) TorCicuitHandler() http.HandlerFunc {
	logr.Logger.Info().Msg("TorCicuitHandler")
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			t.creatCircuit(w, r)
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
		default:
			http.Error(w, "forbidden method", http.StatusMethodNotAllowed)
		}
	}
}

func (t tor) creatCircuit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	finalDestination := r.URL.Query().Get("key")
	err := t.node.TorEstablishCircuit(finalDestination, 3)
	logr.Logger.Err(err).Msgf("Error establishing circuit to %s", finalDestination)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}
