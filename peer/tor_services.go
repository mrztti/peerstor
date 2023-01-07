package peer

type TorServices interface {
	TorCreate(addr string) error
}
