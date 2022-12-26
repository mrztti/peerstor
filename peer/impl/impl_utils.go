package impl

import (
	"go.dedis.ch/cs438/types"
)

func compareStatusMessages(myStatus, theirStatus types.StatusMessage) (bool, map[string]uint) {
	theyHaveMessagesILack := len(theirStatus) > len(myStatus)
	seqNumsToSend := make(map[string]uint)

	for origin, mySeq := range myStatus {
		neighbourSeq, ok := theirStatus[origin]
		if !ok || mySeq > neighbourSeq {
			seqNumsToSend[origin] = neighbourSeq
		} else {
			theyHaveMessagesILack = theyHaveMessagesILack || mySeq < neighbourSeq
		}
	}

	for origin, neighbourSeq := range theirStatus {
		mySeq, ok := myStatus[origin]
		theyHaveMessagesILack = theyHaveMessagesILack || !ok || mySeq < neighbourSeq
		if theyHaveMessagesILack {
			break
		}
	}
	return theyHaveMessagesILack, seqNumsToSend
}
