package impl

import (
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

func (n *node) execTorControlMessage(msg types.Message, pkt transport.Packet) error {
	return nil
}

// func (n *node) torStartDH(addr string) error {
// 	in := []int{0, 1, 2}
// 	randomIndex := rand.Intn(len(in))
// 	pick := in[randomIndex]

// 	dh, err := dhkx.GetGroup(pick)
// 	if err != nil {
// 		return err
// 	}

// 	priv, err := dh.GeneratePrivateKey(nil)

// 	if err != nil {
// 		return err
// 	}

// }
