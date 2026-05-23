package span

type FileID string

type Point struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

type Span struct {
	File      FileID `json:"file,omitempty"`
	StartByte int    `json:"start_byte,omitempty"`
	EndByte   int    `json:"end_byte,omitempty"`
	Start     Point  `json:"start"`
	End       Point  `json:"end"`
}

func (s Span) IsZero() bool {
	return s.File == "" &&
		s.StartByte == 0 &&
		s.EndByte == 0 &&
		s.Start == (Point{}) &&
		s.End == (Point{})
}
