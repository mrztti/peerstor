package impl

import (
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) execTorRelayMessage(msg types.Message, pkt transport.Packet) error {
	var err error
	torRelayMessage, ok := msg.(*types.TorRelayMessage)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: execTorRelayMessage failed, the message is not of the expected type. the message: %v", n.addr, torRelayMessage)
		return err
	}
	return nil
}

func (n *node) execTorControlMessage(msg types.Message, pkt transport.Packet) error {
	var err error
	torControlMessage, ok := msg.(*types.TorControlMessage)
	if !ok {
		logr.Logger.Err(err).Msgf("[%s]: execTorControlMessage failed, the message is not of the expected type. the message: %v", n.addr, torControlMessage)
		return err
	}
	return nil
}
