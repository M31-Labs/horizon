package span

type FileID string

type Point struct {
	Line   int
	Column int
}

type Span struct {
	File      FileID
	StartByte int
	EndByte   int
	Start     Point
	End       Point
}

func (s Span) IsZero() bool {
	return s.File == "" &&
		s.StartByte == 0 &&
		s.EndByte == 0 &&
		s.Start == (Point{}) &&
		s.End == (Point{})
}
