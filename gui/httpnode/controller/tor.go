package controller

import (
	"encoding/hex"
	"net/http"
	"strconv"

	"github.com/rs/zerolog"
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
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

func (t tor) TorRoutingTableHandler() http.HandlerFunc {
	logr.Logger.Info().Msg("TorCicuitHandler")
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			t.getRoutingTable(w, r)
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
		default:
			http.Error(w, "forbidden method", http.StatusMethodNotAllowed)
		}
	}
}

func (t tor) TorDHKeyHandler() http.HandlerFunc {
	logr.Logger.Info().Msg("TorDHKeyHandler")
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			t.getDHKey(w, r)
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
		default:
			http.Error(w, "forbidden method", http.StatusMethodNotAllowed)
		}
	}
}

func (t tor) TorCurlHandler() http.HandlerFunc {
	logr.Logger.Info().Msg("TorCurlHandler")
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			t.curl(w, r)
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
		default:
			http.Error(w, "forbidden method", http.StatusMethodNotAllowed)
		}
	}
}

func (t tor) curl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	url := r.URL.Query().Get("key")
	circID := r.URL.Query().Get("val")

	httpReq := types.TorHTTPRequest{
		URL:    url,
		Method: types.Get,
	}
	err := t.node.TorSendHTTPRequest(circID, httpReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{\"status\": \"ok\"}"))
}

func (t tor) creatCircuit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	finalDestination := r.URL.Query().Get("key")
	val := r.URL.Query().Get("value")
	i, err := strconv.Atoi(val)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = t.node.TorEstablishCircuit(finalDestination, i)
	logr.Logger.Err(err).Msgf("Error establishing circuit to %s", finalDestination)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{\"status\": \"ok\"}"))
}

func (t tor) getRoutingTable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	entries := t.node.GetTorRoutingEntries()
	tmp := "["
	i := 0
	for k, v := range entries {
		tmp += "{ \"CircuitID\": \"" + k + "\", \"NextHop\": \"" + v.NextHop + "\"}"
		if i != len(entries)-1 {
			tmp += ","
		}
		i++
	}
	tmp += "]"

	w.Write([]byte(tmp))
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func (t tor) getDHKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	keys := t.node.GetSymKeys()
	// enc := json.NewEncoder(w)
	// enc.SetIndent("", "\t")
	tmp := "["
	i := 0
	logr.Logger.Info().Msgf("keys: %v", keys)
	for k, v := range keys {
		vStr := hex.EncodeToString(v)
		tmp += "{ \"Peer\": \"" + k + "\", \"Key\": \"" + vStr + "\"}"
		if i != len(keys)-1 {
			tmp += ","
		}
		i++
	}
	tmp += "]"
	logr.Logger.Info().Msgf("tmp: %v", tmp)
	w.Write([]byte(tmp))
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}
