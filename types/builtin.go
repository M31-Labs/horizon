package types

type Builtin string

const (
	BuiltinCurrentPID  Builtin = "current_pid"
	BuiltinCurrentPPID Builtin = "current_ppid"
	BuiltinCurrentUID  Builtin = "current_uid"
	BuiltinCurrentComm Builtin = "current_comm"
)
