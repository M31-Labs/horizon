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

func current_comm(dst *[16]uint8) {
	_ = dst
}
