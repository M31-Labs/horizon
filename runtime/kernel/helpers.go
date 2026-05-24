package kernel

func current_pid() uint32 {
	return 0
}

func current_ppid() uint32 {
	return 0
}

func current_uid() uint32 {
	return 0
}

func ktime_get_ns() uint64 {
	return 0
}

func current_comm(dst *[16]uint8) {
	_ = dst
}

func probe_read_user_str[T any](dst *T, unsafePtr uint64) int64 {
	_, _ = dst, unsafePtr
	return 0
}
