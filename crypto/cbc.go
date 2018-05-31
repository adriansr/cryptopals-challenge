package crypto

import (
	"crypto/cipher"
	"github.com/adriansr/cryptopals-challenge/crypto/xor"
	"io"
	"github.com/adriansr/cryptopals-challenge/io_util"
)

func CBCEncrypt(input io.Reader, iv []byte, algo cipher.Block) (ciphertext []byte) {
	blockSize := algo.BlockSize()
	buf := make([]byte, blockSize)
	for {
		nr, err := io_util.Read(input, buf)
		// fmt.Fprintf(os.Stderr, "encrypt read %d %v\n", nr ,err)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if nr == 0 {
			break
		}
		if nr != blockSize {
			panic(nr)
			// TODO: binary.PKCS7Pad(buf, blockSize)
		}
		xor.XORBlocks(buf, iv)
		algo.Encrypt(buf, buf)
		ciphertext = append(ciphertext, buf...)
		copy(iv, buf)
	}
	return ciphertext
}

func CBCDecrypt(input io.Reader, iv []byte, algo cipher.Block) (plaintext []byte) {
	blockSize := algo.BlockSize()
	buf,plain := make([]byte, blockSize), make([]byte, blockSize)
	for {
		nr, err := io_util.Read(input, buf)
		// fmt.Fprintf(os.Stderr, "decrypt read %d %v\n", nr ,err)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if nr == 0 {
			break
		}
		if nr != blockSize {
			panic(nr)
			//binary.PKCS7Pad(buf, 16)
		}
		algo.Decrypt(plain, buf)
		xor.XORBlocks(plain, iv)
		plaintext = append(plaintext, plain...)
		copy(iv, buf)
	}
	return plaintext
}
