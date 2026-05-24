package main

import (
	"bytes"
	"testing"
)

func TestSortAndWriteCounts(t *testing.T) {
	rows := []processCount{
		{Pid: 42, Seen: 1},
		{Pid: 7, Seen: 4},
		{Pid: 3, Seen: 4},
	}
	sortCounts(rows)
	var out bytes.Buffer
	writeCounts(&out, rows)
	if got, want := out.String(), "PID\tEXECS\n3\t4\n7\t4\n42\t1\n"; got != want {
		t.Fatalf("counts output = %q, want %q", got, want)
	}
}
