package kernel

type XDPContext struct{}

type Context = XDPContext

const (
	Aborted  int32 = 0
	Drop     int32 = 1
	Pass     int32 = 2
	Tx       int32 = 3
	Redirect int32 = 4

	EtherTypeIPv4 uint16 = 0x0800

	IPProtoICMP uint8 = 1
	IPProtoTCP  uint8 = 6
	IPProtoUDP  uint8 = 17
)

type Eth struct {
	dst   [6]uint8
	src   [6]uint8
	proto uint16
}

type IPv4 struct {
	version_ihl uint8
	tos         uint8
	total_len   uint16
	id          uint16
	frag_off    uint16
	ttl         uint8
	protocol    uint8
	check       uint16
	src         uint32
	dst         uint32
}

func eth(ctx Context) *Eth {
	_ = ctx
	return nil
}

func ipv4(ctx Context) *IPv4 {
	_ = ctx
	return nil
}
