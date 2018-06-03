package crypto

import (
	"io"
	"github.com/adriansr/cryptopals-challenge/binary"
)

type BlockMode interface {
	Encrypt(io.Reader) []byte
	Decrypt(io.Reader) []byte
}

type BlindEncryptFn func([]byte) []byte

func (fn BlindEncryptFn) GuessBlockSize() int {
	// can't just encrypt 1 byte and look at the output length because
	// the function can be appending some data.
	buf := make([]byte, 1, 64)
	base := len(fn(buf))
	for {
		buf = append(buf, 0)
		cur := len(fn(buf))
		if cur > base {
			return cur - base
		}
	}
}

func (fn BlindEncryptFn) IsECB(blockSize int) bool {
	plaintext := make([]byte, blockSize * 4)
	ciphertext := fn(plaintext)
	repeated, _ := binary.ECBRepeatedBlockCount(ciphertext, blockSize)
	return repeated > 1
}

func (fn BlindEncryptFn) BlindLength() int {
	return len(fn(nil))
}
