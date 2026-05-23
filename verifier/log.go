package verifier

type Log struct {
	Raw string
}

func ParseLog(raw string) Log {
	return Log{Raw: raw}
}
