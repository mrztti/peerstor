package impl

import (
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) execTorControlMessage(msg types.Message, pkt transport.Packet) error {
	return nil
}

func (n *node) torStartDH(addr string) error {
	dhManager, err := n.DHfirstStep()
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error creating DHManager", n.addr)
		return err
	}

}
