package types

import (
	"fmt"
	"math/big"
	"strings"
)

type ControlCommand int
type RelayCommand int
type InnerMessageType int
type HttpMethod int

const (
	Create ControlCommand = iota
	Created
)

const (
	RelayRequest RelayCommand = iota
	RelayResponse
	RelayExtend
	RelayExtended
)

const (
	Text InnerMessageType = iota
	HttpReq
)

const (
	Get HttpMethod = iota
	Post
)

type TorControlMessage struct {
	LastHop   string
	CircuitID string
	Cmd       ControlCommand
	Data      []byte
}

type TorRelayMessage struct {
	LastHop         string
	CircuitID       string
	Cmd             RelayCommand
	Relay           string
	StreamID        string
	Digest          []byte
	Len             uint
	Data            []byte
	DataMessageType InnerMessageType
}

// -----------------------------------------------------------------------------
// TorControlMessage

// NewEmpty implements types.Message.
func (t TorControlMessage) NewEmpty() Message {
	return &TorControlMessage{}
}

// Name implements types.Message.
func (t TorControlMessage) Name() string {
	return "TorControlMessage"
}

// String implements types.Message.
func (t TorControlMessage) String() string {
	return fmt.Sprintf("TorControlMessage{LastHop: %v, circuitID:%v, cmd:%v}",
		t.LastHop, t.CircuitID, t.Cmd)
}

// HTML implements types.Message.
func (t TorControlMessage) HTML() string {
	return t.String()
}

// -----------------------------------------------------------------------------
// TorRelayMessage

// NewEmpty implements types.Message.
func (t TorRelayMessage) NewEmpty() Message {
	return &TorRelayMessage{}
}

// Name implements types.Message.
func (t TorRelayMessage) Name() string {
	return "TorRelayMessage"
}

// String implements types.Message.
func (t TorRelayMessage) String() string {
	return fmt.Sprintf("TorRelayMessage{LastHop: %s, circuitID:%v, cmd:%v, relay:%v, streamID:%s, digest:%v, len:%d }",
		t.LastHop, t.CircuitID, t.Cmd, t.Relay, t.StreamID, t.Digest, t.Len)
}

// HTML implements types.Message.
func (t TorRelayMessage) HTML() string {
	return t.String()
}

type TorClientHello struct {
	GroupDH           *big.Int
	PrimeDH           *big.Int
	ClientPresecretDH []byte
}

type TorServerHello struct {
	ServerPresecretDH []byte
	Signature         []byte
	Source            string
}

type TorHTTPRequest struct {
	Source   string
	Method   HttpMethod // Currently 'GET' or 'POST'
	Url      string
	PostBody string
}

// -----------------------------------------------------------------------------
// TorClientHello

// NewEmpty implements types.Message.
func (t TorClientHello) NewEmpty() Message {
	return &TLSClientHello{}
}

// Name implements types.Message.
func (t TorClientHello) Name() string {
	return "torclienthello"
}

// String implements types.Message.
func (t TorClientHello) String() string {
	out := new(strings.Builder)
	out.WriteString("tlsclienthello{")
	fmt.Fprintf(out, "groupdh:%d, primedh:%d, clientpresecretdh:%d}", t.GroupDH, t.PrimeDH, t.ClientPresecretDH)

	return out.String()
}

func (t TorClientHello) HTML() string {
	return t.String()
}

// -----------------------------------------------------------------------------
// TorServerHello

func (t TorServerHello) NewEmpty() Message {
	return &TorServerHello{}
}

// Name implements types.Message.
func (t TorServerHello) Name() string {
	return "torserverhello"
}

// String implements types.Message.
func (t TorServerHello) String() string {
	return fmt.Sprintf("TorServerHello{presecret:%d}", t.ServerPresecretDH)
}

// HTML implements types.Message.
func (t TorServerHello) HTML() string {
	return t.String()
}

// -----------------------------------------------------------------------------
// TorServerHello

func (t TorHTTPRequest) NewEmpty() Message {
	return &TorHTTPRequest{}
}

// Name implements types.Message.
func (t TorHTTPRequest) Name() string {
	return "TorHTTPRequest"
}

// String implements types.Message.
func (t TorHTTPRequest) String() string {
	return fmt.Sprintf("TorHTTPRequest{source:%s}", t.Source)
}

// HTML implements types.Message.
func (t TorHTTPRequest) HTML() string {
	return t.String()
}
