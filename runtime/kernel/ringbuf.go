package kernel

type Ringbuf[T any] struct{}

func (Ringbuf[T]) reserve() *T {
	return nil
}

func (Ringbuf[T]) submit(v *T) {
	_ = v
}

func (Ringbuf[T]) discard(v *T) {
	_ = v
}
