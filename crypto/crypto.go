package crypto

import (
	"io"
)

type BlockMode interface {
	Encrypt(io.Reader) []byte
	Decrypt(io.Reader) []byte
}
