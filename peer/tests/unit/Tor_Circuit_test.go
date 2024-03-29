package unit

import (
	"log"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
)

func Test_Tor_Circuit_Create_Inject(t *testing.T) {
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
	err := node1.EstablishTLSConnection(addr)
	require.NoError(t, err)
	time.Sleep(time.Second)

	n1key := node1.GetSymKey(addr)
	n2key := node2.GetSymKey(node1.GetAddr())

	log.Printf("n1key: %v", n1key)
	log.Printf("n2key: %v", n2key)

	require.Greater(t, len(n1key), 0)
	require.Greater(t, len(n2key), 0)

	require.Equal(t, n1key, n2key)
	node1.TorCreate(node2.GetAddr(), "somethingrandom")
	time.Sleep(time.Second)
	require.Greater(t, len(node1.GetCircuitIDs()), 0)

}
func Test_Tor_Circuit_Create(t *testing.T) {
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
	err := node1.EstablishTLSConnection(addr)
	require.NoError(t, err)
	time.Sleep(time.Second)

	n1key := node1.GetSymKey(addr)
	n2key := node2.GetSymKey(node1.GetAddr())

	log.Printf("n1key: %v", n1key)
	log.Printf("n2key: %v", n2key)

	require.Greater(t, len(n1key), 0)
	require.Greater(t, len(n2key), 0)

	require.Equal(t, n1key, n2key)
	node1.TorCreate(node2.GetAddr(), "somethingrandom")
	time.Sleep(time.Second)
	require.Greater(t, len(node1.GetCircuitIDs()), 0)

}

func Test_Tor_Circuit_Routing_Simple_Inject(t *testing.T) {
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

	addr := node2.GetAddr()
	err := node1.EstablishTLSConnection(addr)
	require.NoError(t, err)
	time.Sleep(time.Second)

	n1key := node1.GetSymKey(addr)
	n2key := node2.GetSymKey(node1.GetAddr())

	log.Printf("n1key: %v", n1key)
	log.Printf("n2key: %v", n2key)

	require.Greater(t, len(n1key), 0)
	require.Greater(t, len(n2key), 0)

	require.Equal(t, n1key, n2key)
	node1.TorCreate(node2.GetAddr(), "somethingrandom")
	time.Sleep(time.Second)

	node2TorRouting := node2.GetTorRoutingEntries()

	require.Len(t, node2TorRouting, 1)
	for _, v := range node2TorRouting {
		require.Equal(t, v.NextHop, node1.GetAddr())
	}

}

func Test_Tor_Circuit_Routing_Simple(t *testing.T) {
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
	err := node1.EstablishTLSConnection(addr)
	require.NoError(t, err)
	time.Sleep(time.Second)

	n1key := node1.GetSymKey(addr)
	n2key := node2.GetSymKey(node1.GetAddr())

	log.Printf("n1key: %v", n1key)
	log.Printf("n2key: %v", n2key)

	require.Greater(t, len(n1key), 0)
	require.Greater(t, len(n2key), 0)

	require.Equal(t, n1key, n2key)
	node1.TorCreate(node2.GetAddr(), "somethingrandom")
	time.Sleep(time.Second)

	node2TorRouting := node2.GetTorRoutingEntries()

	require.Len(t, node2TorRouting, 1)
	for _, v := range node2TorRouting {
		require.Equal(t, v.NextHop, node1.GetAddr())
	}

}

func Test_Tor_Circuit_Public_Encryption(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	handler3, _ := fake.GetHandler(t)

	publicKeyN1, privateKeyN1 := GenerateKeyPair()
	publicKeyN2, privateKeyN2 := GenerateKeyPair()
	publicKeyN3, privateKeyN3 := GenerateKeyPair()

	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN1, privateKeyN1))
	defer alice.Stop()
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN2, privateKeyN2))
	defer bob.Stop()
	charlie := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN3, privateKeyN3))
	defer charlie.Stop()

	//node1 <-> node2 <-> node3
	alice.SetAsmKey(bob.GetAddr(), publicKeyN2)
	alice.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	bob.SetAsmKey(alice.GetAddr(), publicKeyN1)
	bob.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	charlie.SetAsmKey(bob.GetAddr(), publicKeyN2)
	charlie.SetAsmKey(alice.GetAddr(), publicKeyN1)

	bytesToEncrypt := []byte("Tor is the best")
	log.Default().Printf("Bytes to encrypt: %v", bytesToEncrypt)
	log.Default().Printf("Bob addr: %v", bob.GetAddr())
	encMsg, err := alice.EncryptPublicTor(bob.GetAddr(), bytesToEncrypt)
	require.NoError(t, err)
	require.Greater(t, len(encMsg), 0)
	require.NotEqual(t, encMsg, bytesToEncrypt)

	decryptedBytes, err := bob.DecryptPublicTor(encMsg)
	require.NoError(t, err)
	require.Equal(t, decryptedBytes, bytesToEncrypt)
}

func Test_Tor_Circuit_Symmetric_Encryption(t *testing.T) {
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

	node2.AddPeer(node1.GetAddr())
	node1.AddPeer(node2.GetAddr())

	time.Sleep(time.Second)

	node1.SetAsmKey(node2.GetAddr(), publicKeyN2)
	node2.SetAsmKey(node1.GetAddr(), publicKeyN1)

	//node1 <-> node2

	node1.EstablishTLSConnection(node2.GetAddr())

	time.Sleep(time.Second)

	require.Equal(t, node1.GetSymKey(node2.GetAddr()), node2.GetSymKey(node1.GetAddr()))

	// Test Node1 -> Node2
	messageToEncrypt := []byte("Hello World")
	msg := transport.Message{Payload: messageToEncrypt}
	encrypted, err := node1.EncryptSymmetricTor(node2.GetAddr(), msg.Payload)
	require.NoError(t, err)
	require.Greater(t, len(encrypted), 0)
	require.NotEqual(t, msg.Payload, encrypted)
	decrypted, err := node2.DecryptSymmetricTor(node1.GetAddr(), encrypted)
	require.NoError(t, err)
	require.Equal(t, messageToEncrypt, decrypted)

	// Test Node2 -> Node1
	messageToEncrypt = []byte("Yellow World")
	msg = transport.Message{Payload: messageToEncrypt}
	encrypted, err = node2.EncryptSymmetricTor(node1.GetAddr(), msg.Payload)
	require.NoError(t, err)
	require.Greater(t, len(encrypted), 0)
	require.NotEqual(t, msg.Payload, encrypted)
	decrypted, err = node1.DecryptSymmetricTor(node2.GetAddr(), encrypted)
	require.NoError(t, err)
	require.Equal(t, messageToEncrypt, decrypted)
}

func Test_Tor_Circuit_Extend_Inject(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	handler3, _ := fake.GetHandler(t)

	publicKeyN1, privateKeyN1 := GenerateKeyPair()
	publicKeyN2, privateKeyN2 := GenerateKeyPair()
	publicKeyN3, privateKeyN3 := GenerateKeyPair()

	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN1, privateKeyN1))
	defer alice.Stop()
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN2, privateKeyN2))
	defer bob.Stop()
	charlie := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN3, privateKeyN3))
	defer charlie.Stop()

	bob.AddPeer(alice.GetAddr())
	alice.AddPeer(bob.GetAddr())
	bob.AddPeer(charlie.GetAddr())
	charlie.AddPeer(bob.GetAddr())

	time.Sleep(time.Second)

	//node1 <-> node2 <-> node3
	alice.SetAsmKey(bob.GetAddr(), publicKeyN2)
	alice.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	bob.SetAsmKey(alice.GetAddr(), publicKeyN1)
	bob.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	charlie.SetAsmKey(bob.GetAddr(), publicKeyN2)
	charlie.SetAsmKey(alice.GetAddr(), publicKeyN1)

	alice.SetRoutingEntry(charlie.GetAddr(), bob.GetAddr())
	charlie.SetRoutingEntry(alice.GetAddr(), bob.GetAddr())

	alice.EstablishTLSConnection(bob.GetAddr())
	charlie.EstablishTLSConnection(bob.GetAddr())
	alice.EstablishTLSConnection(charlie.GetAddr())

	time.Sleep(time.Second)

	require.Greater(t, len(alice.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(bob.GetAddr())), 0)

	require.Equal(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.Equal(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(alice.GetAddr()))

	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(charlie.GetAddr()))

	alice.TorCreate(bob.GetAddr(), "somethingrandom")
	time.Sleep(time.Second)
	log.Default().Printf("alice circuit ids: %v", alice.GetCircuitIDs())
	alice.TorExtend(charlie.GetAddr(), alice.GetCircuitIDs()[0])
	time.Sleep(time.Second)

	aliceAddr := alice.GetAddr()
	bobAddr := bob.GetAddr()
	charlieAddr := charlie.GetAddr()

	aliceKeys := alice.GetSymKeys()
	bobKeys := bob.GetSymKeys()
	charlieKeys := charlie.GetSymKeys()

	delete(aliceKeys, bobAddr)
	delete(aliceKeys, charlieAddr)
	delete(bobKeys, aliceAddr)
	delete(bobKeys, charlieAddr)
	delete(charlieKeys, bobAddr)
	delete(charlieKeys, aliceAddr)

	for dictKey, val := range aliceKeys {
		if strings.Contains(dictKey, bobAddr) {
			for _, value := range bobKeys {
				require.Equal(t, val, value)
			}
		} else {
			for charKey, value := range charlieKeys {
				log.Default().Println(charKey)
				require.Equal(t, val, value)
			}
		}
	}
}

func Test_Tor_Circuit_Extend(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	handler3, _ := fake.GetHandler(t)

	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50))
	defer alice.Stop()
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50))
	defer bob.Stop()
	charlie := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50))
	defer charlie.Stop()

	bob.AddPeer(alice.GetAddr())
	alice.AddPeer(bob.GetAddr())
	bob.AddPeer(charlie.GetAddr())
	charlie.AddPeer(bob.GetAddr())

	time.Sleep(time.Second)

	alice.SetRoutingEntry(charlie.GetAddr(), bob.GetAddr())
	charlie.SetRoutingEntry(alice.GetAddr(), bob.GetAddr())

	alice.EstablishTLSConnection(bob.GetAddr())
	charlie.EstablishTLSConnection(bob.GetAddr())
	alice.EstablishTLSConnection(charlie.GetAddr())

	time.Sleep(time.Second)

	require.Greater(t, len(alice.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(bob.GetAddr())), 0)

	require.Equal(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.Equal(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(alice.GetAddr()))

	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(charlie.GetAddr()))

	alice.TorCreate(bob.GetAddr(), "somethingrandom")
	time.Sleep(time.Second)
	log.Default().Printf("alice circuit ids: %v", alice.GetCircuitIDs())
	alice.TorExtend(charlie.GetAddr(), alice.GetCircuitIDs()[0])
	time.Sleep(time.Second)

	aliceAddr := alice.GetAddr()
	bobAddr := bob.GetAddr()
	charlieAddr := charlie.GetAddr()

	aliceKeys := alice.GetSymKeys()
	bobKeys := bob.GetSymKeys()
	charlieKeys := charlie.GetSymKeys()

	delete(aliceKeys, bobAddr)
	delete(aliceKeys, charlieAddr)
	delete(bobKeys, aliceAddr)
	delete(bobKeys, charlieAddr)
	delete(charlieKeys, bobAddr)
	delete(charlieKeys, aliceAddr)

	for dictKey, val := range aliceKeys {
		if strings.Contains(dictKey, bobAddr) {
			for _, value := range bobKeys {
				require.Equal(t, val, value)
			}
		} else {
			for charKey, value := range charlieKeys {
				log.Default().Println(charKey)
				require.Equal(t, val, value)
			}
		}
	}
}

func Test_Tor_Circuit_Extend_Extend_Inject(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	handler3, _ := fake.GetHandler(t)
	handler4, _ := fake.GetHandler(t)

	publicKeyN1, privateKeyN1 := GenerateKeyPair()
	publicKeyN2, privateKeyN2 := GenerateKeyPair()
	publicKeyN3, privateKeyN3 := GenerateKeyPair()
	publicKeyN4, privateKeyN4 := GenerateKeyPair()

	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN1, privateKeyN1))
	defer alice.Stop()
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN2, privateKeyN2))
	defer bob.Stop()
	charlie := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN3, privateKeyN3))
	defer charlie.Stop()
	detlef := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler4), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN4, privateKeyN4))
	defer detlef.Stop()

	alice.AddPeer(bob.GetAddr())
	bob.AddPeer(alice.GetAddr())
	bob.AddPeer(charlie.GetAddr())
	charlie.AddPeer(bob.GetAddr())
	charlie.AddPeer(detlef.GetAddr())
	detlef.AddPeer(charlie.GetAddr())

	time.Sleep(time.Second)
	//node1 <-> node2 <-> node3 <-> node4
	alice.SetAsmKey(bob.GetAddr(), publicKeyN2)
	alice.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	alice.SetAsmKey(detlef.GetAddr(), publicKeyN4)
	bob.SetAsmKey(alice.GetAddr(), publicKeyN1)
	bob.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	bob.SetAsmKey(detlef.GetAddr(), publicKeyN4)
	charlie.SetAsmKey(bob.GetAddr(), publicKeyN2)
	charlie.SetAsmKey(alice.GetAddr(), publicKeyN1)
	charlie.SetAsmKey(detlef.GetAddr(), publicKeyN4)
	detlef.SetAsmKey(bob.GetAddr(), publicKeyN2)
	detlef.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	detlef.SetAsmKey(alice.GetAddr(), publicKeyN1)

	alice.SetRoutingEntry(charlie.GetAddr(), bob.GetAddr())
	alice.SetRoutingEntry(detlef.GetAddr(), bob.GetAddr())
	bob.SetRoutingEntry(detlef.GetAddr(), charlie.GetAddr())
	charlie.SetRoutingEntry(alice.GetAddr(), bob.GetAddr())
	detlef.SetRoutingEntry(alice.GetAddr(), charlie.GetAddr())
	detlef.SetRoutingEntry(bob.GetAddr(), charlie.GetAddr())

	alice.EstablishTLSConnection(bob.GetAddr())
	charlie.EstablishTLSConnection(bob.GetAddr())
	alice.EstablishTLSConnection(charlie.GetAddr())
	detlef.EstablishTLSConnection(charlie.GetAddr())
	detlef.EstablishTLSConnection(bob.GetAddr())
	detlef.EstablishTLSConnection(alice.GetAddr())

	time.Sleep(time.Second)

	require.Greater(t, len(alice.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(charlie.GetAddr())), 0)

	require.Equal(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.Equal(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(alice.GetAddr()))
	require.Equal(t, alice.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(bob.GetAddr()))
	require.Equal(t, charlie.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(charlie.GetAddr()))

	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))

	err := alice.TorCreate(bob.GetAddr(), "somethingrandom")
	require.NoError(t, err)
	time.Sleep(time.Second)
	log.Default().Printf("alice circuit ids: %v", alice.GetCircuitIDs())
	err = alice.TorExtend(charlie.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	aliceSymKeys := []string{}
	for k := range alice.GetSymKeys() {
		aliceSymKeys = append(aliceSymKeys, k)
	}
	log.Default().Printf("successfully extended to charlie. alice circ ids: %v", aliceSymKeys)
	bobsSymKeys := []string{}
	for k := range bob.GetSymKeys() {
		bobsSymKeys = append(bobsSymKeys, k)
	}
	log.Default().Printf("successfully extended to charlie. bobs circ ids: %v", bobsSymKeys)
	err = alice.TorExtend(detlef.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)

	aliceAddr := alice.GetAddr()
	bobAddr := bob.GetAddr()
	charlieAddr := charlie.GetAddr()
	detlefAddr := detlef.GetAddr()

	aliceKeys := alice.GetSymKeys()
	bobKeys := bob.GetSymKeys()
	charlieKeys := charlie.GetSymKeys()
	detlefKeys := detlef.GetSymKeys()

	delete(aliceKeys, bobAddr)
	delete(aliceKeys, charlieAddr)
	delete(aliceKeys, detlefAddr)
	delete(bobKeys, aliceAddr)
	delete(bobKeys, charlieAddr)
	delete(bobKeys, detlefAddr)
	delete(charlieKeys, bobAddr)
	delete(charlieKeys, aliceAddr)
	delete(charlieKeys, detlefAddr)
	delete(detlefKeys, aliceAddr)
	delete(detlefKeys, bobAddr)
	delete(detlefKeys, charlieAddr)

	for dictKey, val := range aliceKeys {
		if strings.Contains(dictKey, bobAddr) {
			for _, value := range bobKeys {
				require.Equal(t, val, value)
			}
		} else if strings.Contains(dictKey, charlieAddr) {
			for charKey, value := range charlieKeys {
				log.Default().Println(charKey)
				require.Equal(t, val, value)
			}
		} else {
			for _, value := range detlefKeys {
				require.Equal(t, val, value)
			}
		}
	}
}

func Test_Tor_Circuit_Extend_Extend(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	handler3, _ := fake.GetHandler(t)
	handler4, _ := fake.GetHandler(t)

	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50))
	defer alice.Stop()
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50))
	defer bob.Stop()
	charlie := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50))
	defer charlie.Stop()
	detlef := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler4), z.WithAntiEntropy(time.Millisecond*50))
	defer detlef.Stop()

	alice.AddPeer(bob.GetAddr())
	bob.AddPeer(alice.GetAddr())
	bob.AddPeer(charlie.GetAddr())
	charlie.AddPeer(bob.GetAddr())
	charlie.AddPeer(detlef.GetAddr())
	detlef.AddPeer(charlie.GetAddr())

	time.Sleep(time.Second)

	alice.SetRoutingEntry(charlie.GetAddr(), bob.GetAddr())
	alice.SetRoutingEntry(detlef.GetAddr(), bob.GetAddr())
	bob.SetRoutingEntry(detlef.GetAddr(), charlie.GetAddr())
	charlie.SetRoutingEntry(alice.GetAddr(), bob.GetAddr())
	detlef.SetRoutingEntry(alice.GetAddr(), charlie.GetAddr())
	detlef.SetRoutingEntry(bob.GetAddr(), charlie.GetAddr())

	alice.EstablishTLSConnection(bob.GetAddr())
	charlie.EstablishTLSConnection(bob.GetAddr())
	alice.EstablishTLSConnection(charlie.GetAddr())
	detlef.EstablishTLSConnection(charlie.GetAddr())
	detlef.EstablishTLSConnection(bob.GetAddr())
	detlef.EstablishTLSConnection(alice.GetAddr())

	time.Sleep(time.Second)

	require.Greater(t, len(alice.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(charlie.GetAddr())), 0)

	require.Equal(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.Equal(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(alice.GetAddr()))
	require.Equal(t, alice.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(bob.GetAddr()))
	require.Equal(t, charlie.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(charlie.GetAddr()))

	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))

	err := alice.TorCreate(bob.GetAddr(), "somethingrandom")
	require.NoError(t, err)
	time.Sleep(time.Second)
	log.Default().Printf("alice circuit ids: %v", alice.GetCircuitIDs())
	err = alice.TorExtend(charlie.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	aliceSymKeys := []string{}
	for k := range alice.GetSymKeys() {
		aliceSymKeys = append(aliceSymKeys, k)
	}
	log.Default().Printf("successfully extended to charlie. alice circ ids: %v", aliceSymKeys)
	bobsSymKeys := []string{}
	for k := range bob.GetSymKeys() {
		bobsSymKeys = append(bobsSymKeys, k)
	}
	log.Default().Printf("successfully extended to charlie. bobs circ ids: %v", bobsSymKeys)
	err = alice.TorExtend(detlef.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)

	aliceAddr := alice.GetAddr()
	bobAddr := bob.GetAddr()
	charlieAddr := charlie.GetAddr()
	detlefAddr := detlef.GetAddr()

	aliceKeys := alice.GetSymKeys()
	bobKeys := bob.GetSymKeys()
	charlieKeys := charlie.GetSymKeys()
	detlefKeys := detlef.GetSymKeys()

	delete(aliceKeys, bobAddr)
	delete(aliceKeys, charlieAddr)
	delete(aliceKeys, detlefAddr)
	delete(bobKeys, aliceAddr)
	delete(bobKeys, charlieAddr)
	delete(bobKeys, detlefAddr)
	delete(charlieKeys, bobAddr)
	delete(charlieKeys, aliceAddr)
	delete(charlieKeys, detlefAddr)
	delete(detlefKeys, aliceAddr)
	delete(detlefKeys, bobAddr)
	delete(detlefKeys, charlieAddr)

	for dictKey, val := range aliceKeys {
		if strings.Contains(dictKey, bobAddr) {
			for _, value := range bobKeys {
				require.Equal(t, val, value)
			}
		} else if strings.Contains(dictKey, charlieAddr) {
			for charKey, value := range charlieKeys {
				log.Default().Println(charKey)
				require.Equal(t, val, value)
			}
		} else {
			for _, value := range detlefKeys {
				require.Equal(t, val, value)
			}
		}
	}
}

// Redundant test
/* func Test_Tor_Circuit_Extend_Extend_Extend_Inject(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	handler3, _ := fake.GetHandler(t)
	handler4, _ := fake.GetHandler(t)
	handler5, _ := fake.GetHandler(t)

	publicKeyN1, privateKeyN1 := GenerateKeyPair()
	publicKeyN2, privateKeyN2 := GenerateKeyPair()
	publicKeyN3, privateKeyN3 := GenerateKeyPair()
	publicKeyN4, privateKeyN4 := GenerateKeyPair()
	publicKeyN5, privateKeyN5 := GenerateKeyPair()

	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN1, privateKeyN1))
	defer alice.Stop()
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN2, privateKeyN2))
	defer bob.Stop()
	charlie := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN3, privateKeyN3))
	defer charlie.Stop()
	detlef := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler4), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN4, privateKeyN4))
	defer detlef.Stop()
	eliska := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler5), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN5, privateKeyN5))
	defer eliska.Stop()
	//node1 <-> node2 <-> node3 <-> node4

	alice.AddPeer(bob.GetAddr())
	bob.AddPeer(alice.GetAddr())
	bob.AddPeer(charlie.GetAddr())
	charlie.AddPeer(bob.GetAddr())
	charlie.AddPeer(detlef.GetAddr())
	detlef.AddPeer(charlie.GetAddr())
	detlef.AddPeer(eliska.GetAddr())
	eliska.AddPeer(detlef.GetAddr())

	time.Sleep(5 * time.Second)

	alice.SetAsmKey(bob.GetAddr(), publicKeyN2)
	alice.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	alice.SetAsmKey(detlef.GetAddr(), publicKeyN4)
	alice.SetAsmKey(eliska.GetAddr(), publicKeyN5)
	bob.SetAsmKey(alice.GetAddr(), publicKeyN1)
	bob.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	bob.SetAsmKey(detlef.GetAddr(), publicKeyN4)
	bob.SetAsmKey(eliska.GetAddr(), publicKeyN5)
	charlie.SetAsmKey(bob.GetAddr(), publicKeyN2)
	charlie.SetAsmKey(alice.GetAddr(), publicKeyN1)
	charlie.SetAsmKey(detlef.GetAddr(), publicKeyN4)
	charlie.SetAsmKey(eliska.GetAddr(), publicKeyN5)
	detlef.SetAsmKey(bob.GetAddr(), publicKeyN2)
	detlef.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	detlef.SetAsmKey(alice.GetAddr(), publicKeyN1)
	detlef.SetAsmKey(eliska.GetAddr(), publicKeyN5)
	eliska.SetAsmKey(alice.GetAddr(), publicKeyN1)
	eliska.SetAsmKey(bob.GetAddr(), publicKeyN2)
	eliska.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	eliska.SetAsmKey(detlef.GetAddr(), publicKeyN4)

	alice.SetRoutingEntry(charlie.GetAddr(), bob.GetAddr())
	alice.SetRoutingEntry(detlef.GetAddr(), bob.GetAddr())
	alice.SetRoutingEntry(eliska.GetAddr(), bob.GetAddr())
	bob.SetRoutingEntry(detlef.GetAddr(), charlie.GetAddr())
	bob.SetRoutingEntry(eliska.GetAddr(), charlie.GetAddr())
	charlie.SetRoutingEntry(alice.GetAddr(), bob.GetAddr())
	charlie.SetRoutingEntry(eliska.GetAddr(), detlef.GetAddr())
	detlef.SetRoutingEntry(alice.GetAddr(), charlie.GetAddr())
	detlef.SetRoutingEntry(bob.GetAddr(), charlie.GetAddr())
	eliska.SetRoutingEntry(alice.GetAddr(), detlef.GetAddr())
	eliska.SetRoutingEntry(bob.GetAddr(), detlef.GetAddr())
	eliska.SetRoutingEntry(charlie.GetAddr(), detlef.GetAddr())

	alice.EstablishTLSConnection(bob.GetAddr())
	alice.EstablishTLSConnection(charlie.GetAddr())
	charlie.EstablishTLSConnection(bob.GetAddr())
	detlef.EstablishTLSConnection(charlie.GetAddr())
	detlef.EstablishTLSConnection(bob.GetAddr())
	detlef.EstablishTLSConnection(alice.GetAddr())
	eliska.EstablishTLSConnection(detlef.GetAddr())
	eliska.EstablishTLSConnection(charlie.GetAddr())
	eliska.EstablishTLSConnection(bob.GetAddr())
	eliska.EstablishTLSConnection(alice.GetAddr())

	time.Sleep(time.Second)

	require.Greater(t, len(alice.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(detlef.GetAddr())), 0)

	require.Equal(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.Equal(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(alice.GetAddr()))
	require.Equal(t, alice.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(bob.GetAddr()))
	require.Equal(t, charlie.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(charlie.GetAddr()))
	require.Equal(t, alice.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(bob.GetAddr()))
	require.Equal(t, charlie.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(charlie.GetAddr()))
	require.Equal(t, detlef.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(detlef.GetAddr()))

	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))

	err := alice.TorCreate(bob.GetAddr(), "somethingrandom")
	require.NoError(t, err)
	time.Sleep(time.Second)
	log.Default().Printf("alice circuit ids: %v", alice.GetCircuitIDs())
	err = alice.TorExtend(charlie.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	aliceSymKeys := []string{}
	for k := range alice.GetSymKeys() {
		aliceSymKeys = append(aliceSymKeys, k)
	}
	log.Default().Printf("successfully extended to charlie. alice circ ids: %v", aliceSymKeys)
	bobsSymKeys := []string{}
	for k := range bob.GetSymKeys() {
		bobsSymKeys = append(bobsSymKeys, k)
	}
	log.Default().Printf("successfully extended to charlie. bobs circ ids: %v", bobsSymKeys)
	err = alice.TorExtend(detlef.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	alice.TorExtend(eliska.GetAddr(), alice.GetCircuitIDs()[0])
	time.Sleep(time.Second)

	aliceAddr := alice.GetAddr()
	bobAddr := bob.GetAddr()
	charlieAddr := charlie.GetAddr()
	detlefAddr := detlef.GetAddr()
	eliskaAddr := eliska.GetAddr()

	aliceKeys := alice.GetSymKeys()
	bobKeys := bob.GetSymKeys()
	charlieKeys := charlie.GetSymKeys()
	detlefKeys := detlef.GetSymKeys()
	eliskaKeys := eliska.GetSymKeys()

	delete(aliceKeys, bobAddr)
	delete(aliceKeys, charlieAddr)
	delete(aliceKeys, detlefAddr)
	delete(aliceKeys, eliskaAddr)
	delete(bobKeys, aliceAddr)
	delete(bobKeys, charlieAddr)
	delete(bobKeys, detlefAddr)
	delete(bobKeys, eliskaAddr)
	delete(charlieKeys, bobAddr)
	delete(charlieKeys, aliceAddr)
	delete(charlieKeys, detlefAddr)
	delete(charlieKeys, eliskaAddr)
	delete(detlefKeys, aliceAddr)
	delete(detlefKeys, bobAddr)
	delete(detlefKeys, charlieAddr)
	delete(detlefKeys, eliskaAddr)
	delete(eliskaKeys, aliceAddr)
	delete(eliskaKeys, bobAddr)
	delete(eliskaKeys, charlieAddr)
	delete(eliskaKeys, detlefAddr)

	for dictKey, val := range aliceKeys {
		if strings.Contains(dictKey, bobAddr) {
			for _, value := range bobKeys {
				require.Equal(t, val, value)
			}
		} else if strings.Contains(dictKey, charlieAddr) {
			for charKey, value := range charlieKeys {
				log.Default().Println(charKey)
				require.Equal(t, val, value)
			}
		} else if strings.Contains(dictKey, detlefAddr) {
			for _, value := range detlefKeys {
				require.Equal(t, val, value)
			}
		} else if strings.Contains(dictKey, eliskaAddr) {
			for _, value := range eliskaKeys {
				require.Equal(t, val, value)
			}
		}
	}
} */

func Test_Tor_Circuit_Extend_Extend_Extend(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	handler3, _ := fake.GetHandler(t)
	handler4, _ := fake.GetHandler(t)
	handler5, _ := fake.GetHandler(t)

	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50))
	defer alice.Stop()
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50))
	defer bob.Stop()
	charlie := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50))
	defer charlie.Stop()
	detlef := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler4), z.WithAntiEntropy(time.Millisecond*50))
	defer detlef.Stop()
	eliska := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler5), z.WithAntiEntropy(time.Millisecond*50))
	defer eliska.Stop()
	//node1 <-> node2 <-> node3 <-> node4

	alice.AddPeer(bob.GetAddr())
	bob.AddPeer(alice.GetAddr())
	bob.AddPeer(charlie.GetAddr())
	charlie.AddPeer(bob.GetAddr())
	charlie.AddPeer(detlef.GetAddr())
	detlef.AddPeer(charlie.GetAddr())
	detlef.AddPeer(eliska.GetAddr())
	eliska.AddPeer(detlef.GetAddr())

	time.Sleep(time.Second)

	alice.SetRoutingEntry(charlie.GetAddr(), bob.GetAddr())
	alice.SetRoutingEntry(detlef.GetAddr(), bob.GetAddr())
	alice.SetRoutingEntry(eliska.GetAddr(), bob.GetAddr())
	bob.SetRoutingEntry(detlef.GetAddr(), charlie.GetAddr())
	bob.SetRoutingEntry(eliska.GetAddr(), charlie.GetAddr())
	charlie.SetRoutingEntry(alice.GetAddr(), bob.GetAddr())
	charlie.SetRoutingEntry(eliska.GetAddr(), detlef.GetAddr())
	detlef.SetRoutingEntry(alice.GetAddr(), charlie.GetAddr())
	detlef.SetRoutingEntry(bob.GetAddr(), charlie.GetAddr())
	eliska.SetRoutingEntry(alice.GetAddr(), detlef.GetAddr())
	eliska.SetRoutingEntry(bob.GetAddr(), detlef.GetAddr())
	eliska.SetRoutingEntry(charlie.GetAddr(), detlef.GetAddr())

	alice.EstablishTLSConnection(bob.GetAddr())
	alice.EstablishTLSConnection(charlie.GetAddr())
	charlie.EstablishTLSConnection(bob.GetAddr())
	detlef.EstablishTLSConnection(charlie.GetAddr())
	detlef.EstablishTLSConnection(bob.GetAddr())
	detlef.EstablishTLSConnection(alice.GetAddr())
	eliska.EstablishTLSConnection(detlef.GetAddr())
	eliska.EstablishTLSConnection(charlie.GetAddr())
	eliska.EstablishTLSConnection(bob.GetAddr())
	eliska.EstablishTLSConnection(alice.GetAddr())

	time.Sleep(time.Second)

	require.Greater(t, len(alice.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(detlef.GetAddr())), 0)

	require.Equal(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.Equal(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(alice.GetAddr()))
	require.Equal(t, alice.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(bob.GetAddr()))
	require.Equal(t, charlie.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(charlie.GetAddr()))
	require.Equal(t, alice.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(bob.GetAddr()))
	require.Equal(t, charlie.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(charlie.GetAddr()))
	require.Equal(t, detlef.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(detlef.GetAddr()))

	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))

	err := alice.TorCreate(bob.GetAddr(), "somethingrandom")
	require.NoError(t, err)
	time.Sleep(time.Second)
	log.Default().Printf("alice circuit ids: %v", alice.GetCircuitIDs())
	err = alice.TorExtend(charlie.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	aliceSymKeys := []string{}
	for k := range alice.GetSymKeys() {
		aliceSymKeys = append(aliceSymKeys, k)
	}
	log.Default().Printf("successfully extended to charlie. alice circ ids: %v", aliceSymKeys)
	bobsSymKeys := []string{}
	for k := range bob.GetSymKeys() {
		bobsSymKeys = append(bobsSymKeys, k)
	}
	log.Default().Printf("successfully extended to charlie. bobs circ ids: %v", bobsSymKeys)
	err = alice.TorExtend(detlef.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	alice.TorExtend(eliska.GetAddr(), alice.GetCircuitIDs()[0])
	time.Sleep(time.Second)

	aliceAddr := alice.GetAddr()
	bobAddr := bob.GetAddr()
	charlieAddr := charlie.GetAddr()
	detlefAddr := detlef.GetAddr()
	eliskaAddr := eliska.GetAddr()

	aliceKeys := alice.GetSymKeys()
	bobKeys := bob.GetSymKeys()
	charlieKeys := charlie.GetSymKeys()
	detlefKeys := detlef.GetSymKeys()
	eliskaKeys := eliska.GetSymKeys()

	delete(aliceKeys, bobAddr)
	delete(aliceKeys, charlieAddr)
	delete(aliceKeys, detlefAddr)
	delete(aliceKeys, eliskaAddr)
	delete(bobKeys, aliceAddr)
	delete(bobKeys, charlieAddr)
	delete(bobKeys, detlefAddr)
	delete(bobKeys, eliskaAddr)
	delete(charlieKeys, bobAddr)
	delete(charlieKeys, aliceAddr)
	delete(charlieKeys, detlefAddr)
	delete(charlieKeys, eliskaAddr)
	delete(detlefKeys, aliceAddr)
	delete(detlefKeys, bobAddr)
	delete(detlefKeys, charlieAddr)
	delete(detlefKeys, eliskaAddr)
	delete(eliskaKeys, aliceAddr)
	delete(eliskaKeys, bobAddr)
	delete(eliskaKeys, charlieAddr)
	delete(eliskaKeys, detlefAddr)

	for dictKey, val := range aliceKeys {
		if strings.Contains(dictKey, bobAddr) {
			for _, value := range bobKeys {
				require.Equal(t, val, value)
			}
		} else if strings.Contains(dictKey, charlieAddr) {
			for charKey, value := range charlieKeys {
				log.Default().Println(charKey)
				require.Equal(t, val, value)
			}
		} else if strings.Contains(dictKey, detlefAddr) {
			for _, value := range detlefKeys {
				require.Equal(t, val, value)
			}
		} else if strings.Contains(dictKey, eliskaAddr) {
			for _, value := range eliskaKeys {
				require.Equal(t, val, value)
			}
		}
	}
}

// Redundant test
/* func Test_Tor_Circuit_Extend_Circuit_Establish_Inject(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	handler3, _ := fake.GetHandler(t)
	handler4, _ := fake.GetHandler(t)
	handler5, _ := fake.GetHandler(t)

	publicKeyN1, privateKeyN1 := GenerateKeyPair()
	publicKeyN2, privateKeyN2 := GenerateKeyPair()
	publicKeyN3, privateKeyN3 := GenerateKeyPair()
	publicKeyN4, privateKeyN4 := GenerateKeyPair()
	publicKeyN5, privateKeyN5 := GenerateKeyPair()

	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN1, privateKeyN1))
	defer alice.Stop()
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN2, privateKeyN2))
	defer bob.Stop()
	charlie := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN3, privateKeyN3))
	defer charlie.Stop()
	detlef := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler4), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN4, privateKeyN4))
	defer detlef.Stop()
	eliska := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler5), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN5, privateKeyN5))
	defer eliska.Stop()

	alice.AddPeer(bob.GetAddr())
	bob.AddPeer(alice.GetAddr())
	bob.AddPeer(charlie.GetAddr())
	charlie.AddPeer(bob.GetAddr())
	charlie.AddPeer(detlef.GetAddr())
	detlef.AddPeer(charlie.GetAddr())
	detlef.AddPeer(eliska.GetAddr())
	eliska.AddPeer(detlef.GetAddr())

	time.Sleep(10 * time.Second)

	alice.RegisterAsOnionNode()
	bob.RegisterAsOnionNode()
	charlie.RegisterAsOnionNode()
	detlef.RegisterAsOnionNode()
	// eliska.RegisterAsOnionNode()

	//node1 <-> node2 <-> node3 <-> node4
	alice.SetAsmKey(bob.GetAddr(), publicKeyN2)
	alice.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	alice.SetAsmKey(detlef.GetAddr(), publicKeyN4)
	alice.SetAsmKey(eliska.GetAddr(), publicKeyN5)
	bob.SetAsmKey(alice.GetAddr(), publicKeyN1)
	bob.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	bob.SetAsmKey(detlef.GetAddr(), publicKeyN4)
	bob.SetAsmKey(eliska.GetAddr(), publicKeyN5)
	charlie.SetAsmKey(bob.GetAddr(), publicKeyN2)
	charlie.SetAsmKey(alice.GetAddr(), publicKeyN1)
	charlie.SetAsmKey(detlef.GetAddr(), publicKeyN4)
	charlie.SetAsmKey(eliska.GetAddr(), publicKeyN5)
	detlef.SetAsmKey(bob.GetAddr(), publicKeyN2)
	detlef.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	detlef.SetAsmKey(alice.GetAddr(), publicKeyN1)
	detlef.SetAsmKey(eliska.GetAddr(), publicKeyN5)
	eliska.SetAsmKey(alice.GetAddr(), publicKeyN1)
	eliska.SetAsmKey(bob.GetAddr(), publicKeyN2)
	eliska.SetAsmKey(charlie.GetAddr(), publicKeyN3)
	eliska.SetAsmKey(detlef.GetAddr(), publicKeyN4)

	alice.SetRoutingEntry(charlie.GetAddr(), bob.GetAddr())
	alice.SetRoutingEntry(detlef.GetAddr(), bob.GetAddr())
	alice.SetRoutingEntry(eliska.GetAddr(), bob.GetAddr())
	bob.SetRoutingEntry(detlef.GetAddr(), charlie.GetAddr())
	bob.SetRoutingEntry(eliska.GetAddr(), charlie.GetAddr())
	charlie.SetRoutingEntry(alice.GetAddr(), bob.GetAddr())
	charlie.SetRoutingEntry(eliska.GetAddr(), detlef.GetAddr())
	detlef.SetRoutingEntry(alice.GetAddr(), charlie.GetAddr())
	detlef.SetRoutingEntry(bob.GetAddr(), charlie.GetAddr())
	eliska.SetRoutingEntry(alice.GetAddr(), detlef.GetAddr())
	eliska.SetRoutingEntry(bob.GetAddr(), detlef.GetAddr())
	eliska.SetRoutingEntry(charlie.GetAddr(), detlef.GetAddr())

	alice.EstablishTLSConnection(bob.GetAddr())
	alice.EstablishTLSConnection(charlie.GetAddr())
	charlie.EstablishTLSConnection(bob.GetAddr())
	detlef.EstablishTLSConnection(charlie.GetAddr())
	detlef.EstablishTLSConnection(bob.GetAddr())
	detlef.EstablishTLSConnection(alice.GetAddr())
	eliska.EstablishTLSConnection(detlef.GetAddr())
	eliska.EstablishTLSConnection(charlie.GetAddr())
	eliska.EstablishTLSConnection(bob.GetAddr())
	eliska.EstablishTLSConnection(alice.GetAddr())

	time.Sleep(5 * time.Second)

	require.Greater(t, len(alice.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(detlef.GetAddr())), 0)

	require.Equal(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.Equal(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(alice.GetAddr()))
	require.Equal(t, alice.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(bob.GetAddr()))
	require.Equal(t, charlie.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(charlie.GetAddr()))
	require.Equal(t, alice.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(bob.GetAddr()))
	require.Equal(t, charlie.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(charlie.GetAddr()))
	require.Equal(t, detlef.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(detlef.GetAddr()))

	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))

	circuitLen := 4
	err := alice.TorEstablishCircuit(eliska.GetAddr(), circuitLen)
	time.Sleep(2 * time.Second)

	require.NoError(t, err)

	aliceAddr := alice.GetAddr()
	bobAddr := bob.GetAddr()
	charlieAddr := charlie.GetAddr()
	detlefAddr := detlef.GetAddr()
	eliskaAddr := eliska.GetAddr()

	aliceKeys := alice.GetSymKeys()
	bobKeys := bob.GetSymKeys()
	charlieKeys := charlie.GetSymKeys()
	detlefKeys := detlef.GetSymKeys()
	eliskaKeys := eliska.GetSymKeys()

	delete(aliceKeys, bobAddr)
	delete(aliceKeys, charlieAddr)
	delete(aliceKeys, detlefAddr)
	delete(aliceKeys, eliskaAddr)
	delete(bobKeys, aliceAddr)
	delete(bobKeys, charlieAddr)
	delete(bobKeys, detlefAddr)
	delete(bobKeys, eliskaAddr)
	delete(charlieKeys, bobAddr)
	delete(charlieKeys, aliceAddr)
	delete(charlieKeys, detlefAddr)
	delete(charlieKeys, eliskaAddr)
	delete(detlefKeys, aliceAddr)
	delete(detlefKeys, bobAddr)
	delete(detlefKeys, charlieAddr)
	delete(detlefKeys, eliskaAddr)
	delete(eliskaKeys, aliceAddr)
	delete(eliskaKeys, bobAddr)
	delete(eliskaKeys, charlieAddr)
	delete(eliskaKeys, detlefAddr)

	require.Equal(t, circuitLen, len(aliceKeys))
	circuitKeysCounter := 0
	for dictKey, val := range aliceKeys {
		if strings.Contains(dictKey, bobAddr) {
			for _, value := range bobKeys {
				require.Equal(t, val, value)
			}
			circuitKeysCounter++
		} else if strings.Contains(dictKey, charlieAddr) {
			for charKey, value := range charlieKeys {
				log.Default().Println(charKey)
				require.Equal(t, val, value)
			}
			circuitKeysCounter++
		} else if strings.Contains(dictKey, detlefAddr) {
			for _, value := range detlefKeys {
				require.Equal(t, val, value)
			}
			circuitKeysCounter++
		} else if strings.Contains(dictKey, eliskaAddr) {
			for _, value := range eliskaKeys {
				require.Equal(t, val, value)
			}
			circuitKeysCounter++
		}
	}

	require.Equal(t, circuitLen, circuitKeysCounter)
} */

func Test_Tor_Circuit_Extend_Circuit_Establish(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)
	handler3, _ := fake.GetHandler(t)
	handler4, _ := fake.GetHandler(t)
	handler5, _ := fake.GetHandler(t)

	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50))
	defer alice.Stop()
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50))
	defer bob.Stop()
	charlie := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50))
	defer charlie.Stop()
	detlef := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler4), z.WithAntiEntropy(time.Millisecond*50))
	defer detlef.Stop()
	eliska := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler5), z.WithAntiEntropy(time.Millisecond*50))
	defer eliska.Stop()

	alice.AddPeer(bob.GetAddr())
	bob.AddPeer(alice.GetAddr())
	bob.AddPeer(charlie.GetAddr())
	charlie.AddPeer(bob.GetAddr())
	charlie.AddPeer(detlef.GetAddr())
	detlef.AddPeer(charlie.GetAddr())
	detlef.AddPeer(eliska.GetAddr())
	eliska.AddPeer(detlef.GetAddr())

	time.Sleep(time.Second)
	//node1 <-> node2 <-> node3 <-> node4

	alice.RegisterAsOnionNode()
	bob.RegisterAsOnionNode()
	charlie.RegisterAsOnionNode()
	detlef.RegisterAsOnionNode()

	alice.SetRoutingEntry(charlie.GetAddr(), bob.GetAddr())
	alice.SetRoutingEntry(detlef.GetAddr(), bob.GetAddr())
	alice.SetRoutingEntry(eliska.GetAddr(), bob.GetAddr())
	bob.SetRoutingEntry(detlef.GetAddr(), charlie.GetAddr())
	bob.SetRoutingEntry(eliska.GetAddr(), charlie.GetAddr())
	charlie.SetRoutingEntry(alice.GetAddr(), bob.GetAddr())
	charlie.SetRoutingEntry(eliska.GetAddr(), detlef.GetAddr())
	detlef.SetRoutingEntry(alice.GetAddr(), charlie.GetAddr())
	detlef.SetRoutingEntry(bob.GetAddr(), charlie.GetAddr())
	eliska.SetRoutingEntry(alice.GetAddr(), detlef.GetAddr())
	eliska.SetRoutingEntry(bob.GetAddr(), detlef.GetAddr())
	eliska.SetRoutingEntry(charlie.GetAddr(), detlef.GetAddr())

	alice.EstablishTLSConnection(bob.GetAddr())
	alice.EstablishTLSConnection(charlie.GetAddr())
	charlie.EstablishTLSConnection(bob.GetAddr())
	detlef.EstablishTLSConnection(charlie.GetAddr())
	detlef.EstablishTLSConnection(bob.GetAddr())
	detlef.EstablishTLSConnection(alice.GetAddr())
	eliska.EstablishTLSConnection(detlef.GetAddr())
	eliska.EstablishTLSConnection(charlie.GetAddr())
	eliska.EstablishTLSConnection(bob.GetAddr())
	eliska.EstablishTLSConnection(alice.GetAddr())

	time.Sleep(time.Second)

	require.Greater(t, len(alice.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(alice.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(bob.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(charlie.GetSymKey(detlef.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(detlef.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(alice.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(bob.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(charlie.GetAddr())), 0)
	require.Greater(t, len(eliska.GetSymKey(detlef.GetAddr())), 0)

	require.Equal(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.Equal(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(alice.GetAddr()))
	require.Equal(t, alice.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(bob.GetAddr()))
	require.Equal(t, charlie.GetSymKey(detlef.GetAddr()), detlef.GetSymKey(charlie.GetAddr()))
	require.Equal(t, alice.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(alice.GetAddr()))
	require.Equal(t, bob.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(bob.GetAddr()))
	require.Equal(t, charlie.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(charlie.GetAddr()))
	require.Equal(t, detlef.GetSymKey(eliska.GetAddr()), eliska.GetSymKey(detlef.GetAddr()))

	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(bob.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(charlie.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), alice.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), bob.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, bob.GetSymKey(charlie.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))
	require.NotEqual(t, alice.GetSymKey(bob.GetAddr()), charlie.GetSymKey(detlef.GetAddr()))

	randomNodes, err := alice.GetAllOnionNodes()
	require.NoError(t, err)
	log.Default().Printf("Alices onion routers: %v", randomNodes)

	circuitLen := 4
	err = alice.TorEstablishCircuit(eliska.GetAddr(), circuitLen)
	time.Sleep(2 * time.Second)
	require.NoError(t, err)

	aliceAddr := alice.GetAddr()
	bobAddr := bob.GetAddr()
	charlieAddr := charlie.GetAddr()
	detlefAddr := detlef.GetAddr()
	eliskaAddr := eliska.GetAddr()

	aliceKeys := alice.GetSymKeys()
	bobKeys := bob.GetSymKeys()
	charlieKeys := charlie.GetSymKeys()
	detlefKeys := detlef.GetSymKeys()
	eliskaKeys := eliska.GetSymKeys()

	delete(aliceKeys, bobAddr)
	delete(aliceKeys, charlieAddr)
	delete(aliceKeys, detlefAddr)
	delete(aliceKeys, eliskaAddr)
	delete(bobKeys, aliceAddr)
	delete(bobKeys, charlieAddr)
	delete(bobKeys, detlefAddr)
	delete(bobKeys, eliskaAddr)
	delete(charlieKeys, bobAddr)
	delete(charlieKeys, aliceAddr)
	delete(charlieKeys, detlefAddr)
	delete(charlieKeys, eliskaAddr)
	delete(detlefKeys, aliceAddr)
	delete(detlefKeys, bobAddr)
	delete(detlefKeys, charlieAddr)
	delete(detlefKeys, eliskaAddr)
	delete(eliskaKeys, aliceAddr)
	delete(eliskaKeys, bobAddr)
	delete(eliskaKeys, charlieAddr)
	delete(eliskaKeys, detlefAddr)

	require.Equal(t, circuitLen, len(aliceKeys))
	circuitKeysCounter := 0
	for dictKey, val := range aliceKeys {
		if strings.Contains(dictKey, bobAddr) {
			for _, value := range bobKeys {
				require.Equal(t, val, value)
			}
			circuitKeysCounter++
		} else if strings.Contains(dictKey, charlieAddr) {
			for charKey, value := range charlieKeys {
				log.Default().Println(charKey)
				require.Equal(t, val, value)
			}
			circuitKeysCounter++
		} else if strings.Contains(dictKey, detlefAddr) {
			for _, value := range detlefKeys {
				require.Equal(t, val, value)
			}
			circuitKeysCounter++
		} else if strings.Contains(dictKey, eliskaAddr) {
			for _, value := range eliskaKeys {
				require.Equal(t, val, value)
			}
			circuitKeysCounter++
		}
	}

	require.Equal(t, circuitLen, circuitKeysCounter)
}
