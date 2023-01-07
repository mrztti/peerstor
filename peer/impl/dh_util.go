package impl

import (
	"math/rand"

	"github.com/monnand/dhkx"
)

func (n *node) firstStep() (DHManager, error) {
	in := []int{0, 1, 2}
	randomIndex := rand.Intn(len(in))
	pick := in[randomIndex]

	dh, err := dhkx.GetGroup(pick)
	if err != nil {
		return DHManager{}, err
	}

	priv, err := dh.GeneratePrivateKey(nil)

	if err != nil {
		return DHManager{}, err
	}
	dhManager := DHManager{
		dhGroup: dh,
		dhKey:   priv,
	}
	return dhManager
}
