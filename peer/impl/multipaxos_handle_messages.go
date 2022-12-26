package impl

import (
	"go.dedis.ch/cs438/types"
)

func (m *MultiPaxos) preparePromiseMessage(
	prepareMessage *types.PaxosPrepareMessage,
	currentPaxosInstance *PaxosInstance,
) *types.PaxosPromiseMessage {
	var acceptedID uint
	if currentPaxosInstance.acceptedValue != nil {
		acceptedID = uint(currentPaxosInstance.acceptedID.Get())
	}
	return &types.PaxosPromiseMessage{
		Step:          prepareMessage.Step,
		ID:            prepareMessage.ID,
		AcceptedID:    acceptedID,
		AcceptedValue: currentPaxosInstance.acceptedValue,
	}
}
