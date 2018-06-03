package crypto

import (
	"crypto/cipher"
	"io"
	"github.com/adriansr/cryptopals-challenge/util"
	"github.com/adriansr/cryptopals-challenge/binary"
)

type ECBBlockMode struct {
	cipher cipher.Block
}

func NewECBBlockMode(cipher cipher.Block) BlockMode {
	return &ECBBlockMode{cipher}
}

func (ecb *ECBBlockMode) Encrypt(input io.Reader) (ciphertext []byte) {
	blockSize := ecb.cipher.BlockSize()
	buf := make([]byte, blockSize)

	for {
		nr, err := util.Read(input, buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if nr == 0 {
			break
		}
		if nr != blockSize {
			// TODO: What to do with padding?
			buf = binary.PKCS7Pad(buf[:nr], blockSize)
		}
		ecb.cipher.Encrypt(buf, buf)
		ciphertext = append(ciphertext, buf...)
	}
	return ciphertext
}

func (ecb *ECBBlockMode) Decrypt(input io.Reader) (plaintext []byte) {
	blockSize := ecb.cipher.BlockSize()
	buf := make([]byte, blockSize)

	for {
		nr, err := util.Read(input, buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if nr == 0 {
			break
		}
		if nr != blockSize {
			panic(nr)
		}
		ecb.cipher.Decrypt(buf, buf)
		plaintext = append(plaintext, buf...)
	}
	return plaintext
}
