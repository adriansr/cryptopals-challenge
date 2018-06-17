package crypto

import (
	"crypto/cipher"
	"github.com/adriansr/cryptopals-challenge/crypto/xor"
	"io"
	"github.com/adriansr/cryptopals-challenge/util"
)

type CBCBlockMode struct {
	cipher cipher.Block
	iv []byte
}

func NewCBCBlockMode(iv []byte, cipher cipher.Block) BlockMode {
	if len(iv) != cipher.BlockSize() {
		panic(len(iv))
	}
	return &CBCBlockMode{
		cipher: cipher,
		iv: iv,
	}
}

func (cbc *CBCBlockMode) Encrypt(input io.Reader) (ciphertext []byte) {
	blockSize := cbc.cipher.BlockSize()
	buf := make([]byte, blockSize)
	iv := make([]byte, blockSize)
	if len := copy(iv, cbc.iv); len != blockSize {
		panic(len)
	}

	for {
		nr, err := util.Read(input, buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if nr == 0 {
			break
		}
		if nr != blockSize {
			panic("input to encrypt not padded")
		}
		xor.XORBlocks(buf, iv)
		cbc.cipher.Encrypt(buf, buf)
		ciphertext = append(ciphertext, buf...)
		copy(iv, buf)
	}
	return ciphertext
}

func (cbc *CBCBlockMode) Decrypt(input io.Reader) (plaintext []byte) {
	blockSize := cbc.cipher.BlockSize()
	buf,plain := make([]byte, blockSize), make([]byte, blockSize)
	iv := make([]byte, blockSize)
	copy(iv, cbc.iv)

	for {
		nr, err := util.Read(input, buf)
		//fmt.Fprintf(os.Stderr, "decrypt read %d %v\n", nr ,err)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if nr == 0 {
			break
		}
		if nr != blockSize {
			panic(nr)
		}
		cbc.cipher.Decrypt(plain, buf)
		xor.XORBlocks(plain, iv)
		plaintext = append(plaintext, plain...)
		copy(iv, buf)
	}
	return plaintext
}
