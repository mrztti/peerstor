package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/channel"
)

func Test_DH_TwoNodeSetup(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50))
	defer node2.Stop()

	// node1 <-> node2
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	addr := node2.GetAddr()
	node1.CreateDHSymmetricKey(addr)
	time.Sleep(time.Second)

	n1key := node1.GetSymKey(addr)
	n2key := node2.GetSymKey(node1.GetAddr())

	require.Greater(t, len(n1key), 0)
	require.Greater(t, len(n2key), 0)

	require.Equal(t, n1key, n2key)
}

func Test_DH_ThreeNodeSetup(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	handler3, _ := fake.GetHandler(t)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50))
	defer node2.Stop()
	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50))
	defer node3.Stop()

	//node1 <-> node2 <-> node3

	node2.AddPeer(node1.GetAddr())
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node3.GetAddr())
	node3.AddPeer(node2.GetAddr())

	node1.SetRoutingEntry(node3.GetAddr(), node2.GetAddr())
	node3.SetRoutingEntry(node1.GetAddr(), node2.GetAddr())

	node1.CreateDHSymmetricKey(node2.GetAddr())
	node3.CreateDHSymmetricKey(node2.GetAddr())
	node1.CreateDHSymmetricKey(node3.GetAddr())

	time.Sleep(time.Second)

	require.Greater(t, len(node1.GetSymKey(node2.GetAddr())), 0)
	require.Greater(t, len(node2.GetSymKey(node3.GetAddr())), 0)
	require.Greater(t, len(node2.GetSymKey(node1.GetAddr())), 0)
	require.Greater(t, len(node1.GetSymKey(node3.GetAddr())), 0)

	require.Greater(t, len(node3.GetSymKey(node1.GetAddr())), 0)
	require.Greater(t, len(node3.GetSymKey(node2.GetAddr())), 0)

	require.Equal(t, node1.GetSymKey(node2.GetAddr()), node2.GetSymKey(node1.GetAddr()))
	require.Equal(t, node2.GetSymKey(node3.GetAddr()), node3.GetSymKey(node2.GetAddr()))
	require.Equal(t, node1.GetSymKey(node3.GetAddr()), node3.GetSymKey(node1.GetAddr()))

	require.NotEqual(t, node1.GetSymKey(node2.GetAddr()), node2.GetSymKey(node3.GetAddr()))
	require.NotEqual(t, node1.GetSymKey(node3.GetAddr()), node3.GetSymKey(node2.GetAddr()))
	require.NotEqual(t, node1.GetSymKey(node2.GetAddr()), node1.GetSymKey(node3.GetAddr()))

}
