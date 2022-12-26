package udp

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"go.dedis.ch/cs438/logr"
	"go.dedis.ch/cs438/transport"
)

const bufSize = 65000

// NewUDP returns a new udp transport implementation.
func NewUDP() transport.Transport {
	return &UDP{}
}

// UDP implements a transport layer using UDP
//
// - implements transport.Transport
type UDP struct {
	sync.Mutex
}

// CreateSocket implements transport.Transport
func (n *UDP) CreateSocket(address string) (transport.ClosableSocket, error) {
	logr.Logger.Info().Msg("Creating socket.")
	n.Lock()
	defer n.Unlock()
	hostStr, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid IP address", address)
	}
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", hostStr, portStr))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &Socket{
		conn:    conn,
		address: conn.LocalAddr().String(),
		ins:     Packets{},
		outs:    Packets{},
	}, err
}

// Socket implements a network socket using UDP.
//
// - implements transport.Socket
// - implements transport.ClosableSocket
type Socket struct {
	sync.Mutex
	conn    *net.UDPConn
	ins     Packets
	outs    Packets
	address string
}

// Close implements transport.Socket. It returns an error if already closed.
func (s *Socket) Close() error {
	s.Lock()
	defer s.Unlock()
	return s.conn.Close()
}

// Send implements transport.Socket
func (s *Socket) Send(dest string, pkt transport.Packet, timeout time.Duration) error {
	s.Lock()
	defer s.Unlock()
	s.outs.add(pkt)
	bytesToSend, err := pkt.Marshal()
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return err
	}
	if timeout > 0 {
		err = s.conn.SetWriteDeadline(time.Now().Add(timeout))
	}
	if err != nil {
		return err
	}
	bytesSent, err := s.conn.WriteToUDP(bytesToSend, addr)
	logr.Logger.Info().Int("bytesSent", bytesSent).Msg("Sent bytes")
	return err
}

// Recv implements transport.Socket. It blocks until a packet is received, or
// the timeout is reached. In the case the timeout is reached, return a
// TimeoutErr.
func (s *Socket) Recv(timeout time.Duration) (transport.Packet, error) {
	var err error
	var packet transport.Packet
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	var incomingBytes = make([]byte, bufSize)
	err = s.conn.SetReadDeadline(deadline)
	if err != nil {
		return packet, err
	}
	bytesRead, _, err := s.conn.ReadFromUDP(incomingBytes)
	if err != nil {
		if os.IsTimeout(err) {
			err = transport.TimeoutError(timeout)
		}
		return packet, err
	}
	incomingBytes = incomingBytes[:bytesRead]
	if bytesRead > bufSize {
		logr.Logger.Warn().Int("bytesRead", bytesRead).
			Int("bufSize", bufSize).
			Msg("Bytes read exceeds buffer size.")
	}
	err = packet.Unmarshal(incomingBytes)
	if err != nil {
		return packet, err
	}
	logr.Logger.Info().Int("bytesRead", bytesRead).Msg("Received bytes")
	s.ins.add(packet)
	return packet, err
}

// GetAddress implements transport.Socket. It returns the address assigned. Can
// be useful in the case one provided a :0 address, which makes the system use a
// random free port.
func (s *Socket) GetAddress() string {
	return s.address
}

// GetIns implements transport.Socket
func (s *Socket) GetIns() []transport.Packet {
	return s.ins.getAll()
}

// GetOuts implements transport.Socket
func (s *Socket) GetOuts() []transport.Packet {
	return s.outs.getAll()
}

type Packets struct {
	sync.Mutex
	data []transport.Packet
}

func (p *Packets) add(pkt transport.Packet) {
	p.Lock()
	defer p.Unlock()

	p.data = append(p.data, pkt.Copy())
}

func (p *Packets) getAll() []transport.Packet {
	p.Lock()
	defer p.Unlock()

	res := make([]transport.Packet, len(p.data))

	for i, pkt := range p.data {
		res[i] = pkt.Copy()
	}

	return res
}
