package kernel

type KprobeContext struct{}
type KretprobeContext struct{}

func arg1(ctx KprobeContext) uint64 {
	_ = ctx
	return 0
}

func arg2(ctx KprobeContext) uint64 {
	_ = ctx
	return 0
}

func arg3(ctx KprobeContext) uint64 {
	_ = ctx
	return 0
}

func arg4(ctx KprobeContext) uint64 {
	_ = ctx
	return 0
}

func arg5(ctx KprobeContext) uint64 {
	_ = ctx
	return 0
}

func ret(ctx KretprobeContext) int64 {
	_ = ctx
	return 0
}
