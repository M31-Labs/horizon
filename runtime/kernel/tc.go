package kernel

type TCContext struct{}

const (
	TCOK         int32 = 0
	TCReclassify int32 = 1
	TCShot       int32 = 2
	TCPipe       int32 = 3
	TCStolen     int32 = 4
	TCRedirect   int32 = 7
)
