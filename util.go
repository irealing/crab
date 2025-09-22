package crab

import (
	"context"
	"crypto/cipher"
	"crypto/sha512"
	"hash"
	"io"
)

type Sha512Reader struct {
	hash   hash.Hash
	source io.Reader
}

// NewSha512Reader 创建一个新的 Sha512Reader
func NewSha512Reader(r io.Reader) *Sha512Reader {
	return &Sha512Reader{
		hash:   sha512.New(),
		source: r,
	}
}

// Read 实现 io.Reader 接口，读取数据并更新哈希值
func (s *Sha512Reader) Read(p []byte) (n int, err error) {
	n, err = s.source.Read(p)
	if n > 0 {
		_, _ = s.hash.Write(p[:n])
	}
	return
}

// Sum 返回当前的 SHA-512 哈希值
func (s *Sha512Reader) Sum() []byte {
	return s.hash.Sum(nil)
}

type EncryptWriter struct {
	stream cipher.Stream
	writer io.Writer
}

func (e *EncryptWriter) Write(p []byte) (n int, err error) {
	e.stream.XORKeyStream(p, p)
	return e.writer.Write(p)
}

type DecryptReader struct {
	stream cipher.Stream
	reader io.Reader
}

func (d *DecryptReader) Read(p []byte) (n int, err error) {
	n, err = d.reader.Read(p)
	if n > 0 {
		d.stream.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

const (
	CopyBufferSize = 32 * 1024
)

func CopyWithContext(ctx context.Context, r io.Reader, w io.Writer) (int64, error) {
	var (
		buf      = make([]byte, CopyBufferSize)
		readErr  error
		writeErr error
		written  int64
		readLen  int
		writeLen int
	)
	for {
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
		}

		readLen, readErr = r.Read(buf)
		if readLen > 0 {
			writeLen, writeErr = w.Write(buf[0:readLen])
			if writeLen > 0 {
				written += int64(writeLen)
			}
			if writeErr != nil {
				return written, writeErr
			}
			if readLen != writeLen {
				return written, io.ErrShortWrite
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				return written, nil
			}
			return written, readErr
		}
	}
}
