package parser

import "fmt"

type ParseError struct {
	Path    string
	Line    int
	Column  int
	Message string
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
