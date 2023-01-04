package unit

import (
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/channel"
)

func TwoNodeSetup(t *testing.T) {
	t.Log("TestSample")
	transp := channel.NewTransport()
	t.Log("Transport created")
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	t.Log("Handlers created")
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50))
	defer node2.Stop()
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())
	t.Log("Nodes created")
	addr := node2.GetAddr()
	t.Log("Address retrieved")
	t.Logf("Node2: %s", addr)
	node1.AliceSendBob(addr)
	time.Sleep(time.Second)
	n1Outs := node1.GetOuts()
	log.Printf("Node1: %d", len(n1Outs))
	n1key := node1.GetSymKey(addr)
	n2key := node2.GetSymKey(node1.GetAddr())
	require.Equal(t, n1key, n2key)

}
