// Behavior tests for generated bindings — roadmap #18.
// These tests verify runtime properties of the generated code that golden
// snapshot comparisons cannot catch: nil-field safety and context cancellation
// unwinding. They live in the generated fixture package so they run against
// the actual generated types and methods.

package bindings

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// TestGeneratedObjectsCloseSurvivesNilFields verifies that the generated
// Objects.Close() method does not panic when all fields are nil. This covers
// the partial-load case where LoadObjectsWithOptions fails partway through
// and the caller still calls Close() on the incomplete object.
func TestGeneratedObjectsCloseSurvivesNilFields(t *testing.T) {
	// All *ebpf.Map and *ebpf.Program fields are nil — this is the zero value
	// that matches the case where loading failed before any object was assigned.
	o := &Objects{}
	if err := o.Close(); err != nil {
		// An error from Close() with all-nil fields would be unusual, but it is
		// not a correctness problem — only a panic is.
		t.Logf("Close returned error with all-nil fields (acceptable): %v", err)
	}
	// Reaching here without a panic is the success condition.
}

// TestGeneratedObjectsCloseNilReceiver verifies the nil receiver guard emitted
// in the generated Close() method: calling Close() on a nil *Objects pointer
// must return nil without panicking.
func TestGeneratedObjectsCloseNilReceiver(t *testing.T) {
	var o *Objects
	if err := o.Close(); err != nil {
		t.Fatalf("nil receiver Close() returned unexpected error: %v", err)
	}
}

// TestGeneratedRingbufReaderUnwindsOnCtxCancel verifies that ReadOpenEvents
// returns promptly (within 200 ms) after the context is cancelled, and that
// the returned error is either context.Canceled or ringbuf.ErrClosed — not a
// hang or an unexpected error.
//
// The test is skipped when bpf(2) is unavailable (e.g. CI runners or
// containers without kernel BPF support).
func TestGeneratedRingbufReaderUnwindsOnCtxCancel(t *testing.T) {
	// Attempt to lift the memlock rlimit before creating the map. Ignore the
	// error; if it fails the map creation will fail too and we skip cleanly.
	_ = rlimit.RemoveMemlock()

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	})
	if err != nil {
		t.Skipf("bpf(2) ringbuf unavailable on this host: %v", err)
	}
	defer m.Close()

	o := &Objects{OpenEvents: m}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- o.ReadOpenEvents(ctx, func(OpenEvent) error { return nil })
	}()

	// Give the goroutine a moment to block inside reader.Read(), then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		// Both context.Canceled and ringbuf.ErrClosed are acceptable unwind
		// signals. A nil error would also be acceptable if the reader happened
		// to drain cleanly, though that is unlikely with an idle ringbuf.
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, ringbuf.ErrClosed) {
			t.Fatalf("ReadOpenEvents returned unexpected error on ctx cancel: %v", err)
		}
		// Success: unwind completed within the timeout.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("ReadOpenEvents did not unwind within 200 ms of context cancellation")
	}
}
