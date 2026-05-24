package kernel

type CgroupConnect struct{}

type Connect = CgroupConnect

const (
	Deny  int32 = 0
	Allow int32 = 1
)

func dst_port(ctx Connect) uint16 {
	_ = ctx
	return 0
}
