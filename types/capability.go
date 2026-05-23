package types

type DangerLevel string

const (
	DangerObserve    DangerLevel = "observe"
	DangerMutate     DangerLevel = "mutate"
	DangerDrop       DangerLevel = "drop"
	DangerBlock      DangerLevel = "block"
	DangerPrivileged DangerLevel = "privileged"
)
