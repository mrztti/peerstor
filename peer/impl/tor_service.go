package impl

import (
	"go.dedis.ch/cs438/logr"
)

func (n *node) torStartDH(addr string) error {
	dhManager, err := n.DHfirstStep()
	if err != nil {
		logr.Logger.Err(err).Msgf("[%s]: Error creating DHManager", n.addr)
		return err
	}

}
