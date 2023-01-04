package types

import (
	"fmt"
	"strings"
)

type TLSPacket struct {
	Source  string
	Content []byte // Uses symmetric key
	Hash    []byte // Uses symmetric key
}

type TLSPacketHello struct {
	Source  string
	Content []byte // Uses asymmetric key
	Hash    []byte // Use asymmetric key
}

type TLSClientHello struct {
	GroupDH           uint
	PrimeDH           uint
	ClientPresecretDH uint
}

type TLSServerHello struct {
	ServerPresecretDH uint
	//SeshkeyDH         uint
}

// -----------------------------------------------------------------------------
// TLSPacket

// NewEmpty implements types.Message.
func (t TLSPacket) NewEmpty() Message {
	return &TLSPacket{}
}

// Name implements types.Message.
func (t TLSPacket) Name() string {
	return "tlspacket"
}

// String implements types.Message.
func (t TLSPacket) String() string {
	return fmt.Sprintf("tlspacket{source:%s, hash: %v}", t.Source, t.Hash)
}

// HTML implements types.Message.
func (t TLSPacket) HTML() string {
	return t.String()
}

// -----------------------------------------------------------------------------
// TLSPacketHello

// NewEmpty implements types.Message.
func (t TLSPacketHello) NewEmpty() Message {
	return &TLSPacketHello{}
}

// Name implements types.Message.
func (t TLSPacketHello) Name() string {
	return "TLSPacketHello"
}

// String implements types.Message.
func (t TLSPacketHello) String() string {
	return fmt.Sprintf("tlspackethello{source:%s}", t.Source)
}

// HTML implements types.Message.
func (t TLSPacketHello) HTML() string {
	return t.String()
}

// -----------------------------------------------------------------------------
// TLSServerHello

// NewEmpty implements types.Message.
func (t TLSServerHello) NewEmpty() Message {
	return &TLSServerHello{}
}

// Name implements types.Message.
func (t TLSServerHello) Name() string {
	return "TLSServerHello"
}

// String implements types.Message.
func (t TLSServerHello) String() string {
	return fmt.Sprintf("tlsserverhello{presecret:%d}", t.ServerPresecretDH)
}

// HTML implements types.Message.
func (t TLSServerHello) HTML() string {
	return t.String()
}

// -----------------------------------------------------------------------------
// TLSClientHello

// NewEmpty implements types.Message.
func (t TLSClientHello) NewEmpty() Message {
	return &TLSClientHello{}
}

// Name implements types.Message.
func (t TLSClientHello) Name() string {
	return "tlsclienthello"
}

// String implements types.Message.
func (t TLSClientHello) String() string {
	out := new(strings.Builder)
	out.WriteString("tlsclienthello{")
	fmt.Fprintf(out, "groupdh:%d, primedh:%d, clientpresecretdh:%d}", t.GroupDH, t.PrimeDH, t.ClientPresecretDH)

	return out.String()
}

// HTML implements types.Message.
func (t TLSClientHello) HTML() string {
	return t.String()
}
