package impl

import (
	"math/big"
	"math/rand"

	"github.com/monnand/dhkx"
)

func (n *node) DHfirstStep() (DHManager, error) {
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
	return dhManager, nil
}

func (n *node) DHfirstStepWithParams(p *big.Int, g *big.Int) (DHManager, error) {
	dh := dhkx.CreateGroup(p, g)
	priv, err := dh.GeneratePrivateKey(nil)
	if err != nil {
		return DHManager{}, err
	}
	dhManager := DHManager{
		dhGroup: dh,
		dhKey:   priv,
	}
	return dhManager, nil
}

func (n *node) DHsecondStep(dhManager DHManager, s []byte) ([]byte, error) {
	aPubKey := dhkx.NewPublicKey(s)
	ck, err := dhManager.dhGroup.ComputeKey(aPubKey, dhManager.dhKey)
	if err != nil {
		return nil, err
	}
	return ck.Bytes(), nil
}
