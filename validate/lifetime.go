package validate

type Lifetime string

const (
	LifetimeLive     Lifetime = "live"
	LifetimeConsumed Lifetime = "consumed"
)
