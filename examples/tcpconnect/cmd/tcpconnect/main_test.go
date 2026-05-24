package main

import "testing"

func TestCommString(t *testing.T) {
	var comm [16]uint8
	copy(comm[:], []byte("curl\x00ignored"))
	if got, want := commString(comm), "curl"; got != want {
		t.Fatalf("commString = %q, want %q", got, want)
	}
}
