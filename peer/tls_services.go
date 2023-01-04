package peer

type TLSServices interface {
	CreateDHSymmetricKey(addr string) error
	GetSymKey(addr string) []byte
}
