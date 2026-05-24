package main

import (
	"os"

	"m31labs.dev/horizon/compiler"
	"m31labs.dev/horizon/compiler/diag"
	"m31labs.dev/horizon/compiler/span"
)

func diagnosticsWithSourceContext(diags []diag.Diagnostic, files []compiler.FileResult) []diag.Diagnostic {
	if len(diags) == 0 {
		if diags == nil {
			return nil
		}
		return []diag.Diagnostic{}
	}
	sources := make(map[span.FileID][]byte, len(files))
	for _, file := range files {
		if file.Path == "" {
			continue
		}
		data, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		sources[span.FileID(file.Path)] = data
	}
	return diag.AttachSourceContexts(diags, sources)
}

func diagnosticsWithPrimarySourceContext(diags []diag.Diagnostic) []diag.Diagnostic {
	if len(diags) == 0 {
		if diags == nil {
			return nil
		}
		return []diag.Diagnostic{}
	}
	sources := map[span.FileID][]byte{}
	for _, diagnostic := range diags {
		file := diagnostic.Primary.File
		if file == "" {
			continue
		}
		if _, ok := sources[file]; ok {
			continue
		}
		data, err := os.ReadFile(string(file))
		if err != nil {
			continue
		}
		sources[file] = data
	}
	return diag.AttachSourceContexts(diags, sources)
}
