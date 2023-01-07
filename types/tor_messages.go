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
	circuitID string
	cmd       ControlCommand
	data      []byte
}

type TorRelayMessage struct {
	circuitID string
	cmd       RelayCommand
	relay     string
	streamID  string
	digest    []byte
	len       uint
	data      []byte
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
	return fmt.Sprintf("TorControlMessage{circuitID:%s, cmd:%s, data:%v }",
		t.circuitID, t.cmd, t.data)
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
	return fmt.Sprintf("TorRelayMessage{circuitID:%s, cmd:%s, relay:%s, streamID:%s, digest:%v, len:%d, data:%v }",
		t.circuitID, t.cmd, t.relay, t.streamID, t.digest, t.len, t.data)
}

// HTML implements types.Message.
func (t TorRelayMessage) HTML() string {
	return t.String()
}

type TorClientHello struct {
	GroupDH           *big.Int
	PrimeDH           *big.Int
	ClientPresecretDH []byte
	Source            string
}

type TorServerHello struct {
	ServerPresecretDH []byte
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
	return fmt.Sprintf("TorClientHello{source:%s presecret:%d}", t.Source, t.ServerPresecretDH)
}

// HTML implements types.Message.
func (t TorServerHello) HTML() string {
	return t.String()
}
