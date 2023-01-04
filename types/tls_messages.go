package types

import (
	"fmt"
	"math/big"
	"strings"
)

type TLSMessage struct {
	Source      string
	ContentType string
	Content     []byte // Uses symmetric key
	Signature   []byte // Uses symmetric key
}

type TLSMessageHello struct {
	Source    string
	Content   []byte // Uses asymmetric key
	Signature []byte // Use asymmetric key
}

type TLSClientHello struct {
	GroupDH           *big.Int
	PrimeDH           *big.Int
	ClientPresecretDH []byte
}

type TLSServerHello struct {
	ServerPresecretDH []byte
	//SeshkeyDH         uint
}

// -----------------------------------------------------------------------------
// TLSMessage

// NewEmpty implements types.Message.
func (t TLSMessage) NewEmpty() Message {
	return &TLSMessage{}
}

// Name implements types.Message.
func (t TLSMessage) Name() string {
	return "tlsMessage"
}

// String implements types.Message.
func (t TLSMessage) String() string {
	return fmt.Sprintf("tlsMessage{source:%s, Signature: %v}", t.Source, t.Signature)
}

// HTML implements types.Message.
func (t TLSMessage) HTML() string {
	return t.String()
}

// -----------------------------------------------------------------------------
// TLSMessageHello

// NewEmpty implements types.Message.
func (t TLSMessageHello) NewEmpty() Message {
	return &TLSMessageHello{}
}

// Name implements types.Message.
func (t TLSMessageHello) Name() string {
	return "TLSMessageHello"
}

// String implements types.Message.
func (t TLSMessageHello) String() string {
	return fmt.Sprintf("tlsMessagehello{source:%s}", t.Source)
}

// HTML implements types.Message.
func (t TLSMessageHello) HTML() string {
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
