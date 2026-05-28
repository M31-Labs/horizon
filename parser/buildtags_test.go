package parser

import (
	"reflect"
	"testing"
)

func TestExtractBuildTagsNoTags(t *testing.T) {
	source := []byte(`package monitor

func OnExec() i32 { return 0 }
`)
	got := ExtractBuildTags(source)
	if len(got) != 0 {
		t.Fatalf("expected no tags, got %v", got)
	}
}

func TestExtractBuildTagsOneTag(t *testing.T) {
	source := []byte(`//hzn:build linux

package monitor
`)
	got := ExtractBuildTags(source)
	want := []string{"linux"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractBuildTagsMultipleTags(t *testing.T) {
	source := []byte(`//hzn:build linux
//hzn:build amd64
//hzn:build kernel>=5.10

package monitor
`)
	got := ExtractBuildTags(source)
	want := []string{"linux", "amd64", "kernel>=5.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractBuildTagsStopsAtFirstNonCommentLine(t *testing.T) {
	source := []byte(`//hzn:build linux

package monitor

//hzn:build darwin
`)
	got := ExtractBuildTags(source)
	want := []string{"linux"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v (directives after the package line must not contribute)", got, want)
	}
}

func TestExtractBuildTagsIgnoresOtherCommentLines(t *testing.T) {
	source := []byte(`// just a leading doc comment
//hzn:build linux
// another aside
//hzn:build amd64

package monitor
`)
	got := ExtractBuildTags(source)
	want := []string{"linux", "amd64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractBuildTagsTrimsSurroundingWhitespace(t *testing.T) {
	source := []byte(`  //hzn:build   linux && !arm64

package monitor
`)
	got := ExtractBuildTags(source)
	want := []string{"linux && !arm64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
