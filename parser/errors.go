package parser

import (
	"fmt"

	"m31labs.dev/horizon/compiler/span"
)

type ParseError struct {
	Path      string
	Line      int
	Column    int
	EndLine   int
	EndColumn int
	StartByte int
	EndByte   int
	Message   string
}

func (e *ParseError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Path == "" {
		return e.Message
	}
	return fmt.Sprintf("%s:%d:%d: %s", e.Path, e.Line, e.Column, e.Message)
}

func (e *ParseError) Span() span.Span {
	if e == nil {
		return span.Span{}
	}
	endLine, endColumn := e.EndLine, e.EndColumn
	if endLine == 0 {
		endLine = e.Line
	}
	if endColumn == 0 {
		endColumn = e.Column
	}
	return span.Span{
		File:      span.FileID(e.Path),
		StartByte: e.StartByte,
		EndByte:   e.EndByte,
		Start:     span.Point{Line: e.Line, Column: e.Column},
		End:       span.Point{Line: endLine, Column: endColumn},
	}
}
