package unit

import (
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
)

func TestTorCreate(t *testing.T) {
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

	node1.SetAsmKey(node2.GetAddr(), publicKeyN2)
	node2.SetAsmKey(node1.GetAddr(), publicKeyN1)

	require.Equal(t, node1.GetPublicKey(), publicKeyN1)
	require.Equal(t, node2.GetPublicKey(), publicKeyN2)

	// node1 <-> node2
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

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
	node1.TorCreate(node2.GetAddr())
	time.Sleep(time.Second)
	require.Greater(t, len(node1.GetCircuitIDs()), 0)

}

func Test_Tor_Routing_Simple(t *testing.T) {
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

	node1.SetAsmKey(node2.GetAddr(), publicKeyN2)
	node2.SetAsmKey(node1.GetAddr(), publicKeyN1)

	require.Equal(t, node1.GetPublicKey(), publicKeyN1)
	require.Equal(t, node2.GetPublicKey(), publicKeyN2)

	// node1 <-> node2
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

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
	node1.TorCreate(node2.GetAddr())
	time.Sleep(time.Second)

	node2TorRouting := node2.GetTorRoutingEntries()

	require.Len(t, node2TorRouting, 1)
	for _, v := range node2TorRouting {
		require.Equal(t, v.NextHop, node1.GetAddr())
	}

}

func Test_Tor_Public_Encryption(t *testing.T) {
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

func Test_Tor_Symmetric_Encryption(t *testing.T) {
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

	node1.SetAsmKey(node2.GetAddr(), publicKeyN2)
	node2.SetAsmKey(node1.GetAddr(), publicKeyN1)

	//node1 <-> node2

	node2.AddPeer(node1.GetAddr())
	node1.AddPeer(node2.GetAddr())
	node1.CreateDHSymmetricKey(node2.GetAddr())

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

func Test_Tor_Extend(t *testing.T) {
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

	bob.AddPeer(alice.GetAddr())
	alice.AddPeer(bob.GetAddr())
	bob.AddPeer(charlie.GetAddr())
	charlie.AddPeer(bob.GetAddr())

	alice.SetRoutingEntry(charlie.GetAddr(), bob.GetAddr())
	charlie.SetRoutingEntry(alice.GetAddr(), bob.GetAddr())

	alice.CreateDHSymmetricKey(bob.GetAddr())
	charlie.CreateDHSymmetricKey(bob.GetAddr())
	alice.CreateDHSymmetricKey(charlie.GetAddr())

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

	alice.TorCreate(bob.GetAddr())
	time.Sleep(time.Second)
	log.Default().Printf("alice circuit ids: %v", alice.GetCircuitIDs())
	alice.TorExtend(charlie.GetAddr(), alice.GetCircuitIDs()[0])
	time.Sleep(time.Second)
	log.Default().Println("alices registered messaged: ", alice.GetRegistry().GetMessages())
	log.Default().Println("charlie registered messaged: ", charlie.GetRegistry().GetMessages())
	log.Default().Println("Alice Symmetric keys: ", alice.GetSymKeys())
	log.Default().Println("Bob Symmetric keys: ", bob.GetSymKeys())
	log.Default().Println("Charlie Symmetric keys: ", charlie.GetSymKeys())

}
