package crab

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
	"io"
)

const cipherKeyLen = 32

type packer[T Header] struct {
	opt       *Option
	allocator HeaderAllocator[T]
}

func NewPacker[T Header](opt *Option, allocator HeaderAllocator[T]) Packer[T] {
	return &packer[T]{opt: opt, allocator: allocator}
}

func (p *packer[T]) Pack(ctx context.Context, input io.Reader, output io.WriteSeeker) error {
	header := p.allocator()
	if len(header.Sign()) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size,except %d got %d", ed25519.SignatureSize, len(header.Sign()))
	}
	if len(header.Seed()) < 1 {
		return fmt.Errorf("invalid seed size")
	}
	_, err := rand.Read(header.Seed())
	if err != nil {
		return err
	}
	passwordReader := hkdf.New(sha512.New, header.Seed(), p.opt.Secret, p.opt.Salt)
	key := make([]byte, cipherKeyLen+aes.BlockSize)
	if _, err = passwordReader.Read(key); err != nil {
		return err
	}
	if err = header.MarshalTo(output); err != nil {
		return fmt.Errorf("marshal header error %w", err)
	}
	blk, err := aes.NewCipher(key[:cipherKeyLen])
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(blk, key[cipherKeyLen:])
	hashReader := NewSha512Reader(input)
	_, err = CopyWithContext(ctx, hashReader, &EncryptWriter{
		stream: stream,
		writer: output,
	})
	hash := hashReader.Sum()
	copy(header.Sign(), ed25519.Sign(p.opt.Key, hash))
	if _, err = output.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return header.MarshalTo(output)
}
