package kernel

type XDPContext struct{}

type Context = XDPContext

const (
	Aborted  int32 = 0
	Drop     int32 = 1
	Pass     int32 = 2
	Tx       int32 = 3
	Redirect int32 = 4
)
