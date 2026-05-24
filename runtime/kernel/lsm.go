package kernel

type LSMContext struct{}

const (
	LSMAllow int32 = 0
	LSMDeny  int32 = -1
)
