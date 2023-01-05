package unit

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
	"go.dedis.ch/cs438/types"
)

func GenerateKeyPair() (rsa.PublicKey, rsa.PrivateKey) {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		log.Println(err)
	}
	return key.PublicKey, *key
}

func Test_Encryption_Asym_KeyConfig(t *testing.T) {
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

	require.Equal(t, node1.GetPublicKeyFromAddr(node2.GetAddr()), node2.GetPublicKey())
	require.Equal(t, node2.GetPublicKeyFromAddr(node1.GetAddr()), node1.GetPublicKey())
}

func TTest_Encryption_Asym_Encryption_Decryption(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)

	publicKeyN1, privateKeyN1 := GenerateKeyPair()
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN1, privateKeyN1))
	defer node1.Stop()

	chat := types.ChatMessage{
		Message: "this is my chat message",
	}
	data, err := json.Marshal(&chat)
	require.NoError(t, err)

	msg := transport.Message{
		Type:    chat.Name(),
		Payload: data,
	}

	encMsg, err := node1.EncryptPublic(node1.GetAddr(), msg)
	require.NoError(t, err)
	require.Greater(t, len(encMsg.Content), 0)
	require.NotEqual(t, msg.Payload, encMsg.Content)

	decMsg, err := node1.DecryptPublic(&encMsg)
	require.NoError(t, err)
	require.Equal(t, msg.Payload, decMsg.Payload)
}

func Test_Encryption_Asym_Encryption_Two_Nodes(t *testing.T) {
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

	chat := types.ChatMessage{
		Message: "this is my chat message",
	}
	data, err := json.Marshal(&chat)
	require.NoError(t, err)

	msg := transport.Message{
		Type:    chat.Name(),
		Payload: data,
	}

	encMsg, err := node1.EncryptPublic(node2.GetAddr(), msg)
	require.NoError(t, err)
	require.Greater(t, len(encMsg.Content), 0)
	require.NotEqual(t, msg.Payload, encMsg.Content)

	decMsg, err := node2.DecryptPublic(&encMsg)
	require.NoError(t, err)
	require.Equal(t, msg.Payload, decMsg.Payload)

}

func Test_Encryption_BreakSign(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)

	publicKeyN1, privateKeyN1 := GenerateKeyPair()
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN1, privateKeyN1))
	defer node1.Stop()

	chat := types.ChatMessage{
		Message: "this is my chat message",
	}
	data, err := json.Marshal(&chat)
	require.NoError(t, err)

	msg := transport.Message{
		Type:    chat.Name(),
		Payload: data,
	}

	encMsg, err := node1.EncryptPublic(node1.GetAddr(), msg)
	require.NoError(t, err)
	encMsg.Signature = []byte("this is a fake signature")
	decMsg, err := node1.DecryptPublic(&encMsg)
	require.Error(t, err)
	require.NotEqual(t, msg.Payload, decMsg.Payload)
}

func Test_DH_Asym_BreakSign_TwoNodes(t *testing.T) {
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

	chat := types.ChatMessage{
		Message: "this is my chat message",
	}
	data, err := json.Marshal(&chat)
	require.NoError(t, err)

	msg := transport.Message{
		Type:    chat.Name(),
		Payload: data,
	}

	encMsg, err := node1.EncryptPublic(node2.GetAddr(), msg)
	require.NoError(t, err)
	require.Greater(t, len(encMsg.Content), 0)
	require.NotEqual(t, msg.Payload, encMsg.Content)

	encMsg.Signature = []byte("this is a fake signature")
	decMsg, err := node2.DecryptPublic(&encMsg)
	require.Error(t, err)
	require.NotEqual(t, msg.Payload, decMsg.Payload)
}
