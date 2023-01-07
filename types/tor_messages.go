package types

import (
	"fmt"
	"math/big"
	"strings"
)

type ControlCommand int
type RelayCommand int

const (
	Create ControlCommand = iota
	Created
)

const (
	RelayData RelayCommand = iota
	RelayConnected
	RelayExtend
	RelayExtended
)

type TorControlMessage struct {
	LastHop   string
	CircuitID string
	Cmd       ControlCommand
	Data      []byte
}

type TorRelayMessage struct {
	LastHop   string
	CircuitID string
	Cmd       RelayCommand
	Relay     string
	StreamID  string
	Digest    []byte
	Len       uint
	Data      []byte
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
	return fmt.Sprintf("TorControlMessage{LastHop: %v, circuitID:%v, cmd:%v, data:%v }",
		t.LastHop, t.CircuitID, t.Cmd, t.Data)
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
	return fmt.Sprintf("TorRelayMessage{LastHop: %s, circuitID:%v, cmd:%v, relay:%v, streamID:%s, digest:%v, len:%d, data:%v }",
		t.LastHop, t.CircuitID, t.Cmd, t.Relay, t.StreamID, t.Digest, t.Len, t.Data)
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

func (t TorServerHello) NewEmpty() Message {
	return &TorServerHello{}
}

// Name implements types.Message.
func (t TorServerHello) Name() string {
	return "torserverhello"
}

// String implements types.Message.
func (t TorServerHello) String() string {
	return fmt.Sprintf("TorClientHello{presecret:%d}", t.ServerPresecretDH)
}

// HTML implements types.Message.
func (t TorServerHello) HTML() string {
	return t.String()
}
