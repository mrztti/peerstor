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
	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/peer/impl"
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

func Test_Encryption_Asym_Encryption_Decryption(t *testing.T) {
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
	require.Greater(t, len(encMsg.SignedCiphertext), 0)
	require.NotEqual(t, msg.Payload, encMsg.SignedCiphertext)

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
	require.Greater(t, len(encMsg.SignedCiphertext), 0)
	require.NotEqual(t, msg.Payload, encMsg.SignedCiphertext)

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
	msgLen := len(encMsg.SignedCiphertext)
	for i := 0; i < 5; i++ {
		encMsg.SignedCiphertext[msgLen-5+i] = byte(i)
	}
	decMsg, err := node1.DecryptPublic(&encMsg)
	log.Default().Printf("error is: %v", err)
	require.Error(t, err)
	require.NotEqual(t, msg.Payload, decMsg.Payload)
}

func Test_Signature_Is_Correct_Size(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)

	publicKeyN1, privateKeyN1 := GenerateKeyPair()
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN1, privateKeyN1))
	defer node1.Stop()

	testMessage := []byte{}
	lastMessageLength := len(testMessage)
	for i := 0; i < 100; i++ {
		testMessage = append(testMessage, []byte("this is a test message")...)
		signature, err := node1.SignMessage(testMessage)
		require.NoError(t, err)
		require.Less(t, lastMessageLength, len(testMessage))
		require.Equal(t, impl.SIGNATURE_SIZE_BYTES, len(signature))
		lastMessageLength = len(testMessage)
	}
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
	require.Greater(t, len(encMsg.SignedCiphertext), 0)
	require.NotEqual(t, msg.Payload, encMsg.SignedCiphertext)

	msgLen := len(encMsg.SignedCiphertext)
	for i := 0; i < 5; i++ {
		encMsg.SignedCiphertext[msgLen-5+i] = byte(i)
	}
	decMsg, err := node2.DecryptPublic(&encMsg)
	require.Error(t, err)
	require.NotEqual(t, msg.Payload, decMsg.Payload)
}
func Test_TLS_Message_Is_Received(t *testing.T) {
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

	node1.SetAsmKey(node2.GetAddr(), publicKeyN2)
	node1.SetAsmKey(node3.GetAddr(), publicKeyN3)
	node2.SetAsmKey(node1.GetAddr(), publicKeyN1)
	node2.SetAsmKey(node3.GetAddr(), publicKeyN3)
	node3.SetAsmKey(node1.GetAddr(), publicKeyN1)
	node3.SetAsmKey(node2.GetAddr(), publicKeyN2)

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

	require.Equal(t, node1.GetSymKey(node2.GetAddr()), node2.GetSymKey(node1.GetAddr()))
	require.Equal(t, node2.GetSymKey(node3.GetAddr()), node3.GetSymKey(node2.GetAddr()))
	require.Equal(t, node1.GetSymKey(node3.GetAddr()), node3.GetSymKey(node1.GetAddr()))

	// Simply try that a message sent via TLS is received by the other node
	chat := types.ChatMessage{
		Message: "this is my chat message",
	}

	node1.SendTLSMessage(node3.GetAddr(), chat)
	time.Sleep(time.Second)

	node3ins := node3.GetIns()
	node3insNoStatus := make([]transport.Packet, 0)

	for _, msg := range node3ins {
		if msg.Msg.Type != "status" {
			node3insNoStatus = append(node3insNoStatus, msg)
		}
	}

	logr.Logger.Warn().Msgf("node3ins: %v", node3insNoStatus)
	node3Reg := node3.GetRegistry().GetMessages()
	logr.Logger.Warn().Msgf("node3Reg: %v", node3Reg)

	// Ensure the message was received
	var chatMsg *types.ChatMessage
	for _, msg := range node3Reg {
		if msg.Name() == chat.Name() {
			chatMsg = msg.(*types.ChatMessage)
		}
	}
	require.Equal(t, chat, *chatMsg)
	// lastMessage := node3ins[len(node3ins)-1]
	// require.Equal(t, chat.Name(), lastMessage.Msg.Type)
}

func Test_TLS_Message_Is_Reliably_Delivered(t *testing.T) {
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
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN2, privateKeyN2), z.WithAutostart(false))
	defer node2.Stop()
	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler3), z.WithAntiEntropy(time.Millisecond*50), z.WithKeys(publicKeyN3, privateKeyN3))
	defer node3.Stop()

	node1.SetAsmKey(node2.GetAddr(), publicKeyN2)
	node1.SetAsmKey(node3.GetAddr(), publicKeyN3)
	// node2.SetAsmKey(node1.GetAddr(), publicKeyN1)
	// node2.SetAsmKey(node3.GetAddr(), publicKeyN3)
	node3.SetAsmKey(node1.GetAddr(), publicKeyN1)
	node3.SetAsmKey(node2.GetAddr(), publicKeyN2)
	//node1 <-> node2 <-> node3

	node2.AddPeer(node1.GetAddr())
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node3.GetAddr())
	node3.AddPeer(node2.GetAddr())

	// Temporarily allow node1 and node3 to communicate directly for key exchange
	node1.AddPeer(node3.GetAddr())
	node3.AddPeer(node1.GetAddr())
	node1.CreateDHSymmetricKey(node3.GetAddr())
	time.Sleep(time.Second)

	// FORCE nodes 1 and 3 to interact via node2 only.
	node1.SetRoutingEntry(node3.GetAddr(), node2.GetAddr())
	node3.SetRoutingEntry(node1.GetAddr(), node2.GetAddr())

	// Ensure that TLS message is reliably delivered even when intermediate node is down while it is sent
	time.Sleep(time.Second)

	// Send while node2 is down
	require.Greater(t, len(node1.GetSymKey(node3.GetAddr())), 0)
	require.Greater(t, len(node3.GetSymKey(node1.GetAddr())), 0)
	require.Equal(t, node1.GetSymKey(node3.GetAddr()), node3.GetSymKey(node1.GetAddr()))

	// Ensure that TLS message is reliably delivered even when intermediate node is down while it is sent
	chat := types.ChatMessage{
		Message: "this is my chat message",
	}

	// Send while node2 is down
	node1.SendTLSMessage(node3.GetAddr(), chat)
	time.Sleep(time.Second)

	// Start node2
	node2.Start()
	node2.AddPeer(node1.GetAddr())
	node2.AddPeer(node3.GetAddr())
	time.Sleep(time.Second)
	// Check node3 received the message
	node3Reg := node3.GetRegistry().GetMessages()
	logr.Logger.Warn().Msgf("node3Reg: %v", node3Reg)

	// Ensure the message was received
	var chatMsg *types.ChatMessage
	for _, msg := range node3Reg {
		if msg.Name() == chat.Name() {
			chatMsg = msg.(*types.ChatMessage)
		}
	}
	require.Equal(t, chat, *chatMsg)
}

func Test_TLS_SymmetricEncryption_Simple(t *testing.T) {
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
	encrypted, err := node1.EncryptSymmetric(node2.GetAddr(), msg)
	require.NoError(t, err)
	require.Greater(t, len(encrypted.SignedCiphertext), 0)
	require.NotEqual(t, msg.Payload, encrypted.SignedCiphertext)
	decrypted, err := node2.DecryptSymmetric(&encrypted)
	require.NoError(t, err)
	require.Equal(t, messageToEncrypt, []byte(decrypted.Payload))

	// Test Node2 -> Node1
	messageToEncrypt = []byte("Yellow World")
	msg = transport.Message{Payload: messageToEncrypt}
	encrypted, err = node2.EncryptSymmetric(node1.GetAddr(), msg)
	require.NoError(t, err)
	require.Greater(t, len(encrypted.SignedCiphertext), 0)
	require.NotEqual(t, msg.Payload, encrypted.SignedCiphertext)
	decrypted, err = node1.DecryptSymmetric(&encrypted)
	require.NoError(t, err)
	require.Equal(t, messageToEncrypt, []byte(decrypted.Payload))
}

func Test_TLS_SymmetricEncryption_BreakSign(t *testing.T) {
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
	encrypted, err := node1.EncryptSymmetric(node2.GetAddr(), transport.Message{Payload: messageToEncrypt})
	require.NoError(t, err)
	decrypted, err := node2.DecryptSymmetric(&encrypted)
	require.NoError(t, err)
	require.Equal(t, messageToEncrypt, []byte(decrypted.Payload))

	log.Default().Printf("\n\n\n\n\n\nBreak the signature")
	// Test Node2 -> Node1
	messageToEncrypt = []byte("Yellow World")
	msg := transport.Message{Payload: messageToEncrypt}
	encrypted, err = node2.EncryptSymmetric(node1.GetAddr(), msg)
	require.NoError(t, err)
	require.Greater(t, len(encrypted.SignedCiphertext), 0)
	require.NotEqual(t, msg.Payload, encrypted.SignedCiphertext)

	// Break the signature
	msgLen := len(encrypted.SignedCiphertext)
	log.Default().Printf("encrypted ciphertext: %v", encrypted.SignedCiphertext)
	for i := 0; i < 5; i++ {
		encrypted.SignedCiphertext[msgLen-5+i] = byte(i)
	}

	log.Default().Printf("corrupted ciphertext: %v", encrypted.SignedCiphertext)
	decrypted, err = node1.DecryptSymmetric(&encrypted)
	require.Error(t, err)
	require.NotEqual(t, msg.Payload, decrypted.Payload)
}
