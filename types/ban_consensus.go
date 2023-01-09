package types

import "fmt"

// -----------------------------------------------------------------------------
// BanPaxosPrepareMessage

// NewEmpty implements types.Message.
func (p BanPaxosPrepareMessage) NewEmpty() Message {
	return &BanPaxosPrepareMessage{}
}

// Name implements types.Message.
func (p BanPaxosPrepareMessage) Name() string {
	return "ban_paxosprepare"
}

// String implements types.Message.
func (p BanPaxosPrepareMessage) String() string {
	return fmt.Sprintf("{ban_paxosprepare %d - %d}", p.Step, p.ID)
}

// HTML implements types.Message.
func (p BanPaxosPrepareMessage) HTML() string {
	return p.String()
}

// -----------------------------------------------------------------------------
// BanPaxosPromiseMessage

// NewEmpty implements types.Message.
func (p BanPaxosPromiseMessage) NewEmpty() Message {
	return &BanPaxosPromiseMessage{}
}

// Name implements types.Message.
func (p BanPaxosPromiseMessage) Name() string {
	return "ban_paxospromise"
}

// String implements types.Message.
func (p BanPaxosPromiseMessage) String() string {
	return fmt.Sprintf("{ban_paxospromise %d - %d (%d: %v)}", p.Step, p.ID,
		p.AcceptedID, p.AcceptedValue)
}

// HTML implements types.Message.
func (p BanPaxosPromiseMessage) HTML() string {
	return p.String()
}

// -----------------------------------------------------------------------------
// BanPaxosProposeMessage

// NewEmpty implements types.Message.
func (p BanPaxosProposeMessage) NewEmpty() Message {
	return &BanPaxosProposeMessage{}
}

// Name implements types.Message.
func (p BanPaxosProposeMessage) Name() string {
	return "ban_paxospropose"
}

// String implements types.Message.
func (p BanPaxosProposeMessage) String() string {
	return fmt.Sprintf("{ban_paxospropose %d - %d (%v)}", p.Step, p.ID, p.Value)
}

// HTML implements types.Message.
func (p BanPaxosProposeMessage) HTML() string {
	return p.String()
}

// -----------------------------------------------------------------------------
// BanPaxosAcceptMessage

// NewEmpty implements types.Message.
func (p BanPaxosAcceptMessage) NewEmpty() Message {
	return &BanPaxosAcceptMessage{}
}

// Name implements types.Message.
func (p BanPaxosAcceptMessage) Name() string {
	return "ban_paxosaccept"
}

// String implements types.Message.
func (p BanPaxosAcceptMessage) String() string {
	return fmt.Sprintf("{ban_paxosaccept %d - %d (%v)}", p.Step, p.ID, p.Value)
}

// HTML implements types.Message.
func (p BanPaxosAcceptMessage) HTML() string {
	return p.String()
}

// -----------------------------------------------------------------------------
// BanTLCMessage

// NewEmpty implements types.Message.
func (p BanTLCMessage) NewEmpty() Message {
	return &BanTLCMessage{}
}

// Name implements types.Message.
func (p BanTLCMessage) Name() string {
	return "ban_tlc"
}

// String implements types.Message.
func (p BanTLCMessage) String() string {
	return fmt.Sprintf("{ban_tlc %d - (%v)}", p.Step, p.Block)
}

// HTML implements types.Message.
func (p BanTLCMessage) HTML() string {
	return p.String()
}
