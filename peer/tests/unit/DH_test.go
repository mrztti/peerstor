package unit

import (
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/channel"
)

func Test_Tor_DH_TwoNodeSetupFail(t *testing.T) {
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
	err := node1.CreateDHSymmetricKey(addr)
	time.Sleep(time.Second)

	require.Error(t, err)
}

func Test_Tor_DH_TwoNodeSetup_Inject(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)

	publicKeyN1, privateKeyN1 := GenerateKeyPair()
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN1, privateKeyN1))
	defer node1.Stop()

	publicKeyN2, privateKeyN2 := GenerateKeyPair()
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN2, privateKeyN2))
	defer node2.Stop()

	// node1 <-> node2
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	time.Sleep(time.Second)

	node1.SetAsmKey(node2.GetAddr(), publicKeyN2)
	node2.SetAsmKey(node1.GetAddr(), publicKeyN1)

	require.Equal(t, node1.GetPublicKey(), publicKeyN1)
	require.Equal(t, node2.GetPublicKey(), publicKeyN2)

	addr := node2.GetAddr()
	err := node1.CreateDHSymmetricKey(addr)
	require.NoError(t, err)
	time.Sleep(time.Second)

	n1key := node1.GetSymKey(addr)
	n2key := node2.GetSymKey(node1.GetAddr())

	log.Printf("n1key: %v", n1key)
	log.Printf("n2key: %v", n2key)

	require.Greater(t, len(n1key), 0)
	require.Greater(t, len(n2key), 0)

	require.Equal(t, n1key, n2key)
}

func Test_Tor_DH_TwoNodeSetup(t *testing.T) {
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

	time.Sleep(time.Second)

	addr := node2.GetAddr()
	err := node1.CreateDHSymmetricKey(addr)
	require.NoError(t, err)
	time.Sleep(time.Second)

	n1key := node1.GetSymKey(addr)
	n2key := node2.GetSymKey(node1.GetAddr())

	log.Printf("n1key: %v", n1key)
	log.Printf("n2key: %v", n2key)

	require.Greater(t, len(n1key), 0)
	require.Greater(t, len(n2key), 0)

	require.Equal(t, n1key, n2key)
}
func Test_Tor_DH_ThreeNodeSetup_Inject_Keys(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	handler3, _ := fake.GetHandler(t)

	publicKeyN1, privateKeyN1 := GenerateKeyPair()
	publicKeyN2, privateKeyN2 := GenerateKeyPair()
	publicKeyN3, privateKeyN3 := GenerateKeyPair()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN1, privateKeyN1))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN2, privateKeyN2))
	defer node2.Stop()
	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN3, privateKeyN3))
	defer node3.Stop()

	node2.AddPeer(node1.GetAddr())
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node3.GetAddr())
	node3.AddPeer(node2.GetAddr())
	time.Sleep(time.Second)

	//node1 <-> node2 <-> node3
	node1.SetAsmKey(node2.GetAddr(), publicKeyN2)
	node1.SetAsmKey(node3.GetAddr(), publicKeyN3)
	node2.SetAsmKey(node1.GetAddr(), publicKeyN1)
	node2.SetAsmKey(node3.GetAddr(), publicKeyN3)
	node3.SetAsmKey(node2.GetAddr(), publicKeyN2)
	node3.SetAsmKey(node1.GetAddr(), publicKeyN1)
	node1.SetRoutingEntry(node3.GetAddr(), node2.GetAddr())
	node3.SetRoutingEntry(node1.GetAddr(), node2.GetAddr())

	node1.CreateDHSymmetricKey(node2.GetAddr())
	node3.CreateDHSymmetricKey(node2.GetAddr())
	node1.CreateDHSymmetricKey(node3.GetAddr())

	time.Sleep(time.Second)

	require.Greater(t, len(node1.GetSymKey(node2.GetAddr())), 0)
	require.Greater(t, len(node1.GetSymKey(node3.GetAddr())), 0)
	require.Greater(t, len(node2.GetSymKey(node3.GetAddr())), 0)
	require.Greater(t, len(node2.GetSymKey(node1.GetAddr())), 0)
	require.Greater(t, len(node3.GetSymKey(node1.GetAddr())), 0)
	require.Greater(t, len(node3.GetSymKey(node2.GetAddr())), 0)

	require.Equal(t, node1.GetSymKey(node2.GetAddr()), node2.GetSymKey(node1.GetAddr()))
	require.Equal(t, node2.GetSymKey(node3.GetAddr()), node3.GetSymKey(node2.GetAddr()))
	require.Equal(t, node1.GetSymKey(node3.GetAddr()), node3.GetSymKey(node1.GetAddr()))

	require.NotEqual(t, node1.GetSymKey(node2.GetAddr()), node2.GetSymKey(node3.GetAddr()))
	require.NotEqual(t, node1.GetSymKey(node3.GetAddr()), node3.GetSymKey(node2.GetAddr()))
	require.NotEqual(t, node1.GetSymKey(node2.GetAddr()), node1.GetSymKey(node3.GetAddr()))

}
func Test_Tor_DH_ThreeNodeSetup_CA_Keys(t *testing.T) {
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

	node2.AddPeer(node1.GetAddr())
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node3.GetAddr())
	node3.AddPeer(node2.GetAddr())
	time.Sleep(time.Second)

	//node1 <-> node2 <-> node3
	node1.SetRoutingEntry(node3.GetAddr(), node2.GetAddr())
	node3.SetRoutingEntry(node1.GetAddr(), node2.GetAddr())

	node1.CreateDHSymmetricKey(node2.GetAddr())
	node3.CreateDHSymmetricKey(node2.GetAddr())
	node1.CreateDHSymmetricKey(node3.GetAddr())

	time.Sleep(time.Second)

	require.Greater(t, len(node1.GetSymKey(node2.GetAddr())), 0)
	require.Greater(t, len(node1.GetSymKey(node3.GetAddr())), 0)
	require.Greater(t, len(node2.GetSymKey(node3.GetAddr())), 0)
	require.Greater(t, len(node2.GetSymKey(node1.GetAddr())), 0)
	require.Greater(t, len(node3.GetSymKey(node1.GetAddr())), 0)
	require.Greater(t, len(node3.GetSymKey(node2.GetAddr())), 0)

	require.Equal(t, node1.GetSymKey(node2.GetAddr()), node2.GetSymKey(node1.GetAddr()))
	require.Equal(t, node2.GetSymKey(node3.GetAddr()), node3.GetSymKey(node2.GetAddr()))
	require.Equal(t, node1.GetSymKey(node3.GetAddr()), node3.GetSymKey(node1.GetAddr()))

	require.NotEqual(t, node1.GetSymKey(node2.GetAddr()), node2.GetSymKey(node3.GetAddr()))
	require.NotEqual(t, node1.GetSymKey(node3.GetAddr()), node3.GetSymKey(node2.GetAddr()))
	require.NotEqual(t, node1.GetSymKey(node2.GetAddr()), node1.GetSymKey(node3.GetAddr()))

}
