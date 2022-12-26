package impl

import "go.dedis.ch/cs438/types"

type ProposePhase1Message struct {
	value *types.PaxosValue
}

// Name implements types.Message.
func (d ProposePhase1Message) Name() string {
	return "proposerphase1"
}
