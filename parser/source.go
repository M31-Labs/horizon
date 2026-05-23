package parser

import (
	"os"

	"m31labs.dev/horizon/compiler/span"
)

type SourceFile struct {
	Path   string
	Bytes  []byte
	FileID span.FileID
}

func ReadSource(path string) (SourceFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SourceFile{}, err
	}
	return SourceFile{
		Path:   path,
		Bytes:  data,
		FileID: span.FileID(path),
	}, nil
}
