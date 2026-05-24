package kernel

type CgroupConnect struct{}

type Connect = CgroupConnect

const (
	Deny  int32 = 0
	Allow int32 = 1
)

const (
	FamilyIPv4  uint32 = 2
	FamilyIPv6  uint32 = 10
	SockStream  uint32 = 1
	SockDgram   uint32 = 2
	ProtocolTCP uint32 = 6
	ProtocolUDP uint32 = 17
)

func family(ctx Connect) uint32 {
	_ = ctx
	return 0
}

func sock_type(ctx Connect) uint32 {
	_ = ctx
	return 0
}

func protocol(ctx Connect) uint32 {
	_ = ctx
	return 0
}

func dst_port(ctx Connect) uint16 {
	_ = ctx
	return 0
}

func dst_ip4(ctx Connect) uint32 {
	_ = ctx
	return 0
}

func src_ip4(ctx Connect) uint32 {
	_ = ctx
	return 0
}

func ip4(a uint8, b uint8, c uint8, d uint8) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}
