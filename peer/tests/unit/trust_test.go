/*
	Tests for the trust module

	Written by Malo RANZETTI
	January 2023
*/

package unit

import (
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/channel"
)

func Test_Trust_NoError(t *testing.T) {
	transp := channel.NewTransport()
	fake := z.NewFakeMessage(t)
	handler1, _ := fake.GetHandler(t)
	handler2, _ := fake.GetHandler(t)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler1), z.WithAntiEntropy(time.Millisecond*50))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50))
	defer node2.Stop()
	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithMessage(fake, handler2), z.WithAntiEntropy(time.Millisecond*50))
	defer node3.Stop()

	// n1 <-> n2 <-> n3
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())
	node2.AddPeer(node3.GetAddr())
	node3.AddPeer(node2.GetAddr())

	time.Sleep(3 * time.Second)

	outs1 := node1.GetSentMessagesByType(CertificateBroadcastMessage{})

	// Every node shoud trust every other node and itself
	nodes := []*z.TestNode{&node1, &node2, &node3}
	for _, n := range nodes {
		for _, n2 := range nodes {
			require.True(t, n.Trusts(n2.GetAddr()))
			log.Info().Msgf("Node %s trusts %s", n.GetAddr(), n2.GetAddr())
		}
	}

	// Check that each node has the PublicKey of the other nodes and itself
	for _, n := range nodes {
		for _, n2 := range nodes {
			res, err := n.GetPeerPublicKey(n2.GetAddr())
			require.NoError(t, err)
			require.NotNil(t, res)
		}
		// Check that node knows 3 nodes
		require.Equal(t, 3, n.TotalKnownNodes())
	}

	// Register n2 as an onion node
	err := node2.RegisterAsOnionNode()
	require.NoError(t, err)

	// Check that nodes have the right onion catalog
	pub, err := node2.GetPeerPublicKey(node2.GetAddr())
	require.NoError(t, err)
	for _, n := range nodes {
		all, err := n.GetAllOnionNodes()
		require.NoError(t, err)
		require.Equal(t, 1, len(all))
		require.Equal(t, pub, all[node2.GetAddr()])
	}

}
