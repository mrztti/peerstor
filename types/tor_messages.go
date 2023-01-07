package types

import (
	"fmt"
)

type TorControlMessage struct {
	circuitID string
	cmd       string
	data      []byte
}

type TorRelayMessage struct {
	circuitID string
	cmd       string
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
