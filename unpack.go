package crab

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
	"io"
)

type unpacked[T Header] struct {
	opt       *Option
	allocator HeaderAllocator[T]
}

func NewUnpacked[T Header](opt *Option, allocator HeaderAllocator[T]) Unpack[T] {
	return &unpacked[T]{opt: opt, allocator: allocator}
}

func (u *unpacked[T]) Unpack(ctx context.Context, input io.Reader, output io.Writer) (T, error) {
	header := u.allocator()
	err := header.UnmarshalFrom(input)
	if err != nil {
		return header, err
	}
	passwordReader := hkdf.New(sha512.New, header.Seed(), u.opt.Secret, u.opt.Salt)
	key := make([]byte, cipherKeyLen+aes.BlockSize)
	if _, err = passwordReader.Read(key); err != nil {
		return header, fmt.Errorf("failed to generate key %w", err)
	}
	blk, err := aes.NewCipher(key[:cipherKeyLen])
	if err != nil {
		return header, fmt.Errorf("failed to create cipher %w", err)
	}
	sha512Reader := NewSha512Reader(&DecryptReader{
		stream: cipher.NewCTR(blk, key[cipherKeyLen:]),
		reader: input,
	})
	if _, err = CopyWithContext(ctx, sha512Reader, output); err != nil {
		return header, fmt.Errorf("failed to copy %w", err)
	}
	hash := sha512Reader.Sum()
	if !ed25519.Verify(u.opt.Key, hash, header.Sign()) {
		return header, fmt.Errorf("invalid signature")
	}
	return header, nil
}
