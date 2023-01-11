package types

import "fmt"

// -----------------------------------------------------------------------------
// BanPaxosPrepareMessage

// NewEmpty implements types.Message.
func (b BanPaxosPrepareMessage) NewEmpty() Message {
	return &BanPaxosPrepareMessage{}
}

// Name implements types.Message.
func (b BanPaxosPrepareMessage) Name() string {
	return "ban_paxosprepare"
}

// String implements types.Message.
func (b BanPaxosPrepareMessage) String() string {
	return fmt.Sprintf("{ban_paxosprepare %d - %d}", b.Step, b.ID)
}

// HTML implements types.Message.
func (b BanPaxosPrepareMessage) HTML() string {
	return b.String()
}

// -----------------------------------------------------------------------------
// BanPaxosPromiseMessage

// NewEmpty implements types.Message.
func (b BanPaxosPromiseMessage) NewEmpty() Message {
	return &BanPaxosPromiseMessage{}
}

// Name implements types.Message.
func (b BanPaxosPromiseMessage) Name() string {
	return "ban_paxospromise"
}

// String implements types.Message.
func (b BanPaxosPromiseMessage) String() string {
	return fmt.Sprintf("{ban_paxospromise %d - %d (%d: %v)}", b.Step, b.ID,
		b.AcceptedID, b.AcceptedValue)
}

// HTML implements types.Message.
func (b BanPaxosPromiseMessage) HTML() string {
	return b.String()
}

// -----------------------------------------------------------------------------
// BanPaxosProposeMessage

// NewEmpty implements types.Message.
func (b BanPaxosProposeMessage) NewEmpty() Message {
	return &BanPaxosProposeMessage{}
}

// Name implements types.Message.
func (b BanPaxosProposeMessage) Name() string {
	return "ban_paxospropose"
}

// String implements types.Message.
func (b BanPaxosProposeMessage) String() string {
	return fmt.Sprintf("{ban_paxospropose %d - %d (%v)}", b.Step, b.ID, b.Value)
}

// HTML implements types.Message.
func (b BanPaxosProposeMessage) HTML() string {
	return b.String()
}

// -----------------------------------------------------------------------------
// BanPaxosAcceptMessage

// NewEmpty implements types.Message.
func (b BanPaxosAcceptMessage) NewEmpty() Message {
	return &BanPaxosAcceptMessage{}
}

// Name implements types.Message.
func (b BanPaxosAcceptMessage) Name() string {
	return "ban_paxosaccept"
}

// String implements types.Message.
func (b BanPaxosAcceptMessage) String() string {
	return fmt.Sprintf("{ban_paxosaccept %d - %d (%v)}", b.Step, b.ID, b.Value)
}

// HTML implements types.Message.
func (b BanPaxosAcceptMessage) HTML() string {
	return b.String()
}

// -----------------------------------------------------------------------------
// BanTLCMessage

// NewEmpty implements types.Message.
func (b BanTLCMessage) NewEmpty() Message {
	return &BanTLCMessage{}
}

// Name implements types.Message.
func (b BanTLCMessage) Name() string {
	return "ban_tlc"
}

// String implements types.Message.
func (b BanTLCMessage) String() string {
	return fmt.Sprintf("{ban_tlc %d - (%v)}", b.Step, b.Block)
}

// HTML implements types.Message.
func (b BanTLCMessage) HTML() string {
	return b.String()
}
