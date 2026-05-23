package main

import "testing"

func TestCommString(t *testing.T) {
	var comm [16]uint8
	copy(comm[:], []byte("git\x00ignored"))
	if got, want := commString(comm), "git"; got != want {
		t.Fatalf("commString = %q, want %q", got, want)
	}
}
