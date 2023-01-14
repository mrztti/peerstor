package unit

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/channel"
	"go.dedis.ch/cs438/types"
)

func mockFetchDataEndpoint(w http.ResponseWriter, r *http.Request, responseMessage map[string]interface{}) {
	statusCode := http.StatusOK

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(responseMessage)
}

func Test_Tor_Messaging_Simple_Injected_Keys(t *testing.T) {
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
	time.Sleep(time.Second)

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

	alice.CreateDHSymmetricKey(bob.GetAddr())
	alice.CreateDHSymmetricKey(charlie.GetAddr())
	charlie.CreateDHSymmetricKey(bob.GetAddr())
	detlef.CreateDHSymmetricKey(charlie.GetAddr())
	detlef.CreateDHSymmetricKey(bob.GetAddr())
	detlef.CreateDHSymmetricKey(alice.GetAddr())
	eliska.CreateDHSymmetricKey(detlef.GetAddr())
	eliska.CreateDHSymmetricKey(charlie.GetAddr())
	eliska.CreateDHSymmetricKey(bob.GetAddr())
	eliska.CreateDHSymmetricKey(alice.GetAddr())

	time.Sleep(time.Second)

	err := alice.TorCreate(bob.GetAddr(), "somethingrandom")
	require.NoError(t, err)
	time.Sleep(time.Second)
	err = alice.TorExtend(charlie.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	err = alice.TorExtend(detlef.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	alice.TorExtend(eliska.GetAddr(), alice.GetCircuitIDs()[0])
	time.Sleep(time.Second)
	msg := []byte("hello jirka")

	log.Default().Printf("\n\n\n\n\n\n\n SENDING MSG TO ELISKA")

	alice.TorRelayRequest(alice.GetCircuitIDs()[0], msg)
	time.Sleep(time.Second)
	eliskaMsg := eliska.GetRegistry().GetMessages()
	for _, m := range eliskaMsg {
		if m.Name() == "TorRelayMessage" {
			log.Default().Printf("MSG: %s", m.Name())
		}
	}
}
func Test_Tor_Messaging_Simple_CA_Keys(t *testing.T) {
	transp := channel.NewTransport()
	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50))
	defer alice.Stop()
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50))
	defer bob.Stop()
	charlie := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50))
	defer charlie.Stop()
	detlef := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50))
	defer detlef.Stop()
	eliska := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50))
	defer eliska.Stop()

	peers := []z.TestNode{alice, bob, charlie, detlef, eliska}
	for _, p := range peers {
		for _, p2 := range peers {
			if p.GetAddr() != p2.GetAddr() {
				p.AddPeer(p2.GetAddr())
			}
		}
	}

	time.Sleep(5 * time.Second)

	/* alice.SetRoutingEntry(charlie.GetAddr(), bob.GetAddr())
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
	eliska.SetRoutingEntry(charlie.GetAddr(), detlef.GetAddr()) */

	alice.CreateDHSymmetricKey(bob.GetAddr())
	alice.CreateDHSymmetricKey(charlie.GetAddr())
	charlie.CreateDHSymmetricKey(bob.GetAddr())
	detlef.CreateDHSymmetricKey(charlie.GetAddr())
	detlef.CreateDHSymmetricKey(bob.GetAddr())
	detlef.CreateDHSymmetricKey(alice.GetAddr())
	eliska.CreateDHSymmetricKey(detlef.GetAddr())
	eliska.CreateDHSymmetricKey(charlie.GetAddr())
	eliska.CreateDHSymmetricKey(bob.GetAddr())
	eliska.CreateDHSymmetricKey(alice.GetAddr())

	err := alice.TorCreate(bob.GetAddr(), "somethingrandom")
	require.NoError(t, err)
	time.Sleep(time.Second)
	err = alice.TorExtend(charlie.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	err = alice.TorExtend(detlef.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	alice.TorExtend(eliska.GetAddr(), alice.GetCircuitIDs()[0])
	time.Sleep(time.Second)
	msg := []byte("hello jirka")

	log.Default().Printf("\n\n\n\n\n\n\n SENDING MSG TO ELISKA")

	alice.TorRelayRequest(alice.GetCircuitIDs()[0], msg)
	time.Sleep(time.Second)
	eliskaMsg := eliska.GetRegistry().GetMessages()
	for _, m := range eliskaMsg {
		if m.Name() == "TorRelayMessage" {
			log.Default().Printf("MSG: %s", m.Name())
		}
	}
}
func Test_Tor_HTTP_Request_CA_Keys(t *testing.T) {
	transp := channel.NewTransport()
	alice := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50))
	defer alice.Stop()
	bob := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50))
	defer bob.Stop()
	charlie := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50))
	defer charlie.Stop()
	detlef := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50))
	defer detlef.Stop()
	eliska := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50))
	defer eliska.Stop()

	peers := []z.TestNode{alice, bob, charlie, detlef, eliska}
	for _, p := range peers {
		for _, p2 := range peers {
			if p.GetAddr() != p2.GetAddr() {
				p.AddPeer(p2.GetAddr())
			}
		}
	}

	time.Sleep(5 * time.Second)

	alice.CreateDHSymmetricKey(bob.GetAddr())
	alice.CreateDHSymmetricKey(charlie.GetAddr())
	charlie.CreateDHSymmetricKey(bob.GetAddr())
	detlef.CreateDHSymmetricKey(charlie.GetAddr())
	detlef.CreateDHSymmetricKey(bob.GetAddr())
	detlef.CreateDHSymmetricKey(alice.GetAddr())
	eliska.CreateDHSymmetricKey(detlef.GetAddr())
	eliska.CreateDHSymmetricKey(charlie.GetAddr())
	eliska.CreateDHSymmetricKey(bob.GetAddr())
	eliska.CreateDHSymmetricKey(alice.GetAddr())

	time.Sleep(2 * time.Second)

	err := alice.TorCreate(bob.GetAddr(), "somethingrandom")
	require.NoError(t, err)
	time.Sleep(time.Second)
	err = alice.TorExtend(charlie.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	err = alice.TorExtend(detlef.GetAddr(), alice.GetCircuitIDs()[0])
	require.NoError(t, err)
	time.Sleep(time.Second)
	alice.TorExtend(eliska.GetAddr(), alice.GetCircuitIDs()[0])
	time.Sleep(time.Second)

	mockServerResponse := make(map[string]interface{})
	mockServerResponse["id"] = "mock"
	mockServerResponse["name"] = "mock"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSpace(r.URL.Path) {
		case "/":
			log.Default().Printf("Request received")
			mockFetchDataEndpoint(w, r, mockServerResponse)
		default:
			http.NotFoundHandler().ServeHTTP(w, r)
		}
	}))

	requestURL := mockServer.URL + "/"
	torHTTPRequest := types.TorHTTPRequest{
		Method: types.Get,
		URL:    requestURL,
	}

	alice.TorSendHTTPRequest(alice.GetCircuitIDs()[0], torHTTPRequest)
	time.Sleep(2 * time.Second)

	expectedMessageReceived := false
	eliskaMsg := eliska.GetRegistry().GetMessages()
	for _, m := range eliskaMsg {
		if m.Name() == "TorRelayMessage" {
			torRelayMsg, ok := m.(*types.TorRelayMessage)
			if !ok {
				t.Fatal("Could not cast to TorRelayMessage")
			}
			if torRelayMsg.DataMessageType == types.HTTPReq {
				var torHTTPReq types.TorHTTPRequest
				err = json.Unmarshal(torRelayMsg.Data, &torHTTPReq)
				require.NoError(t, err)
				require.Equal(t, torHTTPReq.Method, types.Get)
				require.Equal(t, torHTTPReq.URL, requestURL)
				expectedMessageReceived = true
			}
		}
	}

	require.True(t, expectedMessageReceived)
	expectedMessageReceived = false

	aliceMsg := alice.GetRegistry().GetMessages()
	for _, m := range aliceMsg {
		if m.Name() == "TorRelayMessage" {
			torRelayMsg, ok := m.(*types.TorRelayMessage)
			if !ok {
				t.Fatal("Could not cast to TorRelayMessage")
			}
			if torRelayMsg.DataMessageType == types.HTTPReq {
				expectedResponse, err := json.Marshal(mockServerResponse)
				require.NoError(t, err)
				require.Equal(t, string(expectedResponse)+"\n", string(torRelayMsg.Data))
				expectedMessageReceived = true
			}
		}
	}
	require.True(t, expectedMessageReceived)

}
