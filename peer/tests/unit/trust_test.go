/*
	Tests for the trust module

	Includes basic unit tests as well as more advanced comprehensive tests
	Notably, we test whether a malicious node can attack the network using
	certificate spoofing and by trying to override the paxos mechanism

	Written by Malo RANZETTI
	January 2023
*/

package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/logr"
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

	time.Sleep(time.Second)
	nodes := []*z.TestNode{&node1, &node2, &node3}

	// Check that each node has the PublicKey of the other nodes and itself
	for _, n := range nodes {
		for _, n2 := range nodes {
			res, err := n.GetPeerPublicKey(n2.GetAddr())
			require.NoError(t, err)
			require.NotNil(t, res)
		}
		// Check that node knows 3 nodes
		require.Equal(t, uint(3), n.TotalCertifiedPeers())
	}

	// Register n2 as an onion node
	err := node2.RegisterAsOnionNode()
	require.NoError(t, err)

	time.Sleep(time.Second)

	// Check that nodes have the right onion catalog
	pub, err := node2.GetPeerPublicKey(node2.GetAddr())
	require.NoError(t, err)

	m, err := node1.GetAllOnionNodes()
	require.NoError(t, err)
	require.Equal(t, 1, len(m))

	_, err = node2.GetAllOnionNodes()
	require.Error(t, err)

	m, err = node3.GetAllOnionNodes()
	require.NoError(t, err)
	require.Equal(t, 1, len(m))

	adr, k, err := node1.GetRandomOnionNode()
	require.NoError(t, err)
	require.Equal(t, node2.GetAddr(), adr)
	require.Equal(t, &pub, k)

	adr, k, err = node3.GetRandomOnionNode()
	require.NoError(t, err)
	require.Equal(t, node2.GetAddr(), adr)
	require.Equal(t, &pub, k)

	_, _, err = node2.GetRandomOnionNode()
	require.Error(t, err)

	// End of unit test 1

}

func Test_Trust_Ban(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
		z.WithPaxosID(1), z.WithTotalPeers(3))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
		z.WithPaxosID(2), z.WithTotalPeers(3))
	defer node2.Stop()
	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
		z.WithPaxosID(3), z.WithTotalPeers(3))
	defer node3.Stop()

	// n1 <-> n2 <-> n3
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())
	node2.AddPeer(node3.GetAddr())
	node3.AddPeer(node2.GetAddr())
	nodes := []*z.TestNode{&node1, &node2, &node3}
	time.Sleep(time.Second)

	// Register n2 as an onion node
	err := node2.RegisterAsOnionNode()
	require.NoError(t, err)

	time.Sleep(time.Second)

	// --> Node 1 bans node 2
	node1.Ban(node2.GetAddr())
	time.Sleep(5 * time.Second)

	// None of the nodes must have banned node 2
	for _, n := range nodes {
		require.Equal(t, uint(3), n.TotalCertifiedPeers())
		require.False(t, n.HasSharedBan(node2.GetAddr()))
	}
	require.False(t, node1.Trusts(node2.GetAddr()))

	// --> Node 3 bans node 2
	node3.Ban(node2.GetAddr())
	time.Sleep(5 * time.Second)

	// All of the nodes must have banned node 2
	for _, n := range nodes {
		require.True(t, n.HasSharedBan(node2.GetAddr()))
	}
	require.False(t, node1.Trusts(node2.GetAddr()))
	require.False(t, node3.Trusts(node2.GetAddr()))
	require.True(t, node2.Trusts(node2.GetAddr()))

}

func Test_Trust_Scenario(t *testing.T) {
	transp := channel.NewTransport()
	num_nodes := 10
	nodes := make([]z.TestNode, num_nodes)
	for i := range nodes {
		node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
			z.WithPaxosID(uint(i)), z.WithTotalPeers(uint(num_nodes)))
		defer node.Stop()
		nodes[i] = node
	}
	for i := range nodes {
		node := nodes[i]
		for j := range nodes {
			if i == j {
				continue
			}
			node.AddPeer(nodes[j].GetAddr())
		}
	}
	time.Sleep(5 * time.Second)

	// All peers should be certified
	for _, node := range nodes {
		num := node.TotalCertifiedPeers()
		require.Equal(t, uint(num_nodes), num)
	}

	// Register nodes 1,2,3 as onion nodes
	nodes[0].RegisterAsOnionNode()
	nodes[1].RegisterAsOnionNode()
	nodes[2].RegisterAsOnionNode()
	time.Sleep(1 * time.Second)

	// All peers should be certified
	for i, node := range nodes {
		if i < 3 {
			all, err := node.GetAllOnionNodes()
			require.NoError(t, err)
			require.Equal(t, 2, len(all))
		} else {
			all, err := node.GetAllOnionNodes()
			require.NoError(t, err)
			require.Equal(t, 3, len(all))
		}

	}

	logr.Logger.Info().Msg("Init. test passed, launching ban scenario")

	// 1-4 try to ban node 1, 5-9 try to ban node 2 --> Majority deadlock
	for i, node := range nodes {
		if i == 9 {
			break
		}
		if i < 4 {
			node.Ban(nodes[0].GetAddr())
		} else {
			node.Ban(nodes[1].GetAddr())
		}

	}
	time.Sleep(10 * time.Second)

	for _, node := range nodes {
		require.False(t, node.HasSharedBan(nodes[1].GetAddr()))
		require.False(t, node.HasSharedBan(nodes[0].GetAddr()))
	}

	// Node 10 has the deciding vote
	nodes[9].Ban(nodes[1].GetAddr())

	time.Sleep(2 * time.Second)

	for _, node := range nodes {
		require.True(t, node.HasSharedBan(nodes[1].GetAddr()))
		require.False(t, node.HasSharedBan(nodes[0].GetAddr()))
	}

}

func Test_Trust_Attack_Spoof(t *testing.T) {
	transp := channel.NewTransport()
	num_nodes := 10
	nodes := make([]z.TestNode, num_nodes)
	for i := range nodes {
		node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
			z.WithPaxosID(uint(i)), z.WithTotalPeers(uint(num_nodes+1)))
		defer node.Stop()
		nodes[i] = node
	}

	// Add attacker node
	attacker := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
		z.WithPaxosID(uint(10)), z.WithTotalPeers(uint(num_nodes+1)))
	defer attacker.Stop()
	nodes = append(nodes, attacker)

	for i := range nodes {
		node := nodes[i]
		for j := range nodes {
			if i == j {
				continue
			}
			node.AddPeer(nodes[j].GetAddr())
		}
	}
	time.Sleep(3 * time.Second)

	// All peers should be certified

	for _, node := range nodes {
		num := node.TotalCertifiedPeers()
		require.Equal(t, uint(num_nodes+1), num)
	}

	// Attacker starts spoofing attack
	err := attacker.SpoofCertificates(20)
	require.NoError(t, err)

	// All nodes except the attacker try to ban the attacker
	for i := 0; i < num_nodes; i++ {
		nodes[i].Ban(attacker.GetAddr())
	}

	time.Sleep(10 * time.Second)

	// All nodes except the attacker should have banned the attacker
	for i := 0; i < num_nodes; i++ {
		require.False(t, nodes[i].Trusts(attacker.GetAddr()))
	}

	//No one should have added the attacker to the ban list
	for i := 0; i < num_nodes+1; i++ {
		require.False(t, nodes[i].HasSharedBan(attacker.GetAddr()))
	}

	// The network has to be protected from certificate spoofing attacks

}

func Test_Trust_Verify_Certificates(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
		z.WithCertificateVerification())
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
		z.WithCertificateVerification())
	defer node2.Stop()
	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
		z.WithCertificateVerification())
	defer node3.Stop()

	// n1 <-> n2 <-> n3
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())
	node2.AddPeer(node3.GetAddr())
	node3.AddPeer(node2.GetAddr())

	time.Sleep(3 * time.Second)
	nodes := []*z.TestNode{&node1, &node2, &node3}

	// Check that each node has the PublicKey of the other nodes and itself
	for _, n := range nodes {
		for _, n2 := range nodes {
			res, err := n.GetPeerPublicKey(n2.GetAddr())
			require.NoError(t, err)
			require.NotNil(t, res)
		}
		// Check that node knows 3 nodes
		require.Equal(t, uint(3), n.TotalCertifiedPeers())
	}

}

func Test_Trust_Resist_Spoof(t *testing.T) {
	transp := channel.NewTransport()
	num_nodes := 10
	nodes := make([]z.TestNode, num_nodes)

	// This time we enable certificate verification
	for i := range nodes {
		node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
			z.WithPaxosID(uint(i)), z.WithTotalPeers(uint(num_nodes+1)), z.WithCertificateVerification())
		defer node.Stop()
		nodes[i] = node
	}

	// Add attacker node
	attacker := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
		z.WithPaxosID(uint(10)), z.WithTotalPeers(uint(num_nodes+1)), z.WithCertificateVerification())
	defer attacker.Stop()
	nodes = append(nodes, attacker)

	for i := range nodes {
		node := nodes[i]
		for j := range nodes {
			if i == j {
				continue
			}
			node.AddPeer(nodes[j].GetAddr())
		}
	}
	logr.Logger.Info().Msg("===\nWaiting for network to settle...\n===")
	time.Sleep(10 * time.Second)
	attacker.RegisterAsOnionNode()
	time.Sleep(3 * time.Second)

	// All peers should be certified

	for _, node := range nodes {
		num := node.TotalCertifiedPeers()
		require.Equal(t, uint(num_nodes+1), num)
	}

	// Attacker starts spoofing attack
	err := attacker.SpoofCertificates(20)
	require.NoError(t, err)

	// All nodes except the attacker try to ban the attacker
	for i := 0; i < num_nodes/2+1; i++ {
		nodes[i].Ban(attacker.GetAddr())
	}

	time.Sleep(10 * time.Second)

	// All nodes except the attacker should have banned the attacker
	for i := 0; i < num_nodes; i++ {
		require.False(t, nodes[i].Trusts(attacker.GetAddr()))
	}

	//Everyone should have added the attacker to the ban list
	for i := 0; i < num_nodes+1; i++ {
		require.True(t, nodes[i].HasSharedBan(attacker.GetAddr()))
	}

	// The network is protected from certificate spoofing attacks

	// Note: A malicious node can still use a BotNet attack to prevent the network from banning
	// This is solved in the TOR network by using some central authority.

}

func Test_Trust_Resist_Forced_Ban(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
		z.WithCertificateVerification())
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
		z.WithCertificateVerification())
	defer node2.Stop()
	attacker := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithAntiEntropy(time.Millisecond*50),
		z.WithCertificateVerification())
	defer attacker.Stop()

	// n1 <-> n2 <-> n3
	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())
	node2.AddPeer(attacker.GetAddr())
	attacker.AddPeer(node2.GetAddr())

	time.Sleep(3 * time.Second)
	nodes := []*z.TestNode{&node1, &node2, &attacker}

	attacker.Ban(node1.GetAddr())

	time.Sleep(3 * time.Second)

	for _, n := range nodes {
		require.False(t, n.HasSharedBan(node1.GetAddr()))
	}

	// Here the attacker tries to trick the nodes by spamming accept messages and TLC messages
	// If the nodes do not check the proof of the messages, they will succumb to this attack
	attacker.ForceBan(node1.GetAddr())

	time.Sleep(10 * time.Second)

	for _, n := range nodes {
		require.False(t, n.HasSharedBan(node1.GetAddr()))
	}

}
