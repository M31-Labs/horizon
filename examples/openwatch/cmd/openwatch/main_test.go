package main

import "testing"

func TestByteString(t *testing.T) {
	var comm [16]uint8
	copy(comm[:], []byte("cat\x00ignored"))
	if got, want := byteString(comm[:]), "cat"; got != want {
		t.Fatalf("byteString = %q, want %q", got, want)
	}
}
