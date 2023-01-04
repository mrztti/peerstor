package peer

type TLSServices interface {
	AliceSendBob(bobIP string) error
	GetSymKey(addr string) []byte
}
