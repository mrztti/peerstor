package types

// PaxosPrepareMessage defines a prepare message in Paxos
//
// - implements types.Message
// - implemented in HW3
type BanPaxosPrepareMessage struct {
	Step uint
	ID   uint
	// Source is the address of the peer that sends the prepare
	Source string
	Target string
}

// PaxosPromiseMessage defines a promise message in Paxos
//
// - implements types.Message
// - implemented in HW3
type BanPaxosPromiseMessage struct {
	Step uint
	ID   uint

	// Irrelevant if the proposer hasn't accepted any value
	AcceptedID uint
	// Must be nil if the proposer hasn't accepted any value
	AcceptedValue *PaxosValue
	Proof         []byte
	Source        string
}

// PaxosProposeMessage defines a propose message in Paxos
//
// - implements types.Message
// - implemented in HW3
type BanPaxosProposeMessage struct {
	Step  uint
	ID    uint
	Value PaxosValue
}

// PaxosAcceptMessage defines an accept message in Paxos
//
// - implements types.Message
// - implemented in HW3
type BanPaxosAcceptMessage struct {
	Step   uint
	ID     uint
	Value  PaxosValue
	Source string
	Proof  []byte
}

// TLCMessage defines a TLC message
//
// - implements types.Message
// - implemented in HW3
type BanTLCMessage struct {
	Step   uint
	Block  BlockchainBlock
	Source string
	Proof  []byte
}
