package crab

import (
	"context"
	"io"
)

type Header interface {
	MarshalTo(w io.Writer) error
	UnmarshalFrom(r io.Reader) error
	Sign() []byte
	Seed() []byte
}
type Option struct {
	Key    []byte
	Secret []byte
	Salt   []byte
}
type HeaderAllocator[T Header] func() T

type Packer[T Header] interface {
	Pack(ctx context.Context, input io.Reader, output io.WriteSeeker) error
}
type Unpack[T Header] interface {
	Unpack(ctx context.Context, input io.Reader, output io.Writer) (T, error)
}
