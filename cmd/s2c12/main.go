package main

import (
	"crypto/aes"
	"bytes"
	"fmt"
	"os"

	"github.com/adriansr/cryptopals-challenge/crypto"
	"github.com/adriansr/cryptopals-challenge/util"
	"github.com/adriansr/cryptopals-challenge/binary"
	"encoding/base64"
)


var (
	key = util.RandomBytes(aes.BlockSize)
	targetStr =
		"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
		"YnkK"

	target []byte
)

func init() {
	var err error
	if target, err = base64.StdEncoding.DecodeString(targetStr); err != nil {
		panic(err)
	}
}

func blindEncrypt(data []byte) []byte {
	cb, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	plaintext := make([]byte, 0, len(data) + len(target))
	plaintext = append(append(plaintext, data...), target...)

	bm := crypto.NewECBBlockMode(cb)
	return bm.Encrypt(binary.NewPKCS7Reader(bytes.NewReader(plaintext), aes.BlockSize))
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		os.Exit(1)
	}

	fn := crypto.BlindEncryptFn(blindEncrypt)
	blockSize := fn.GuessBlockSize()
	fmt.Fprintf(os.Stderr, "Guessed block size %d\n", blockSize)

	if !fn.IsECB(blockSize) {
		panic("no ECB?")
	}

	empty := make([]byte, blockSize)
	testBlock := make([]byte, blockSize)
	var secret []byte

	n := fn.BlindLength()
	numBlocks := n / blockSize

	first:
	for nBlock := 0; nBlock < numBlocks; nBlock ++ {
		for pad := blockSize - 1; pad >= 0; pad-- {
			curBlock := fn(empty[:pad])[nBlock*blockSize:(nBlock+1)*blockSize]
			found := false
			var testR []byte
			for i := 0; !found && i < 256; i++ {
				testBlock[blockSize-1] = byte(i)
				testR = fn(testBlock)[:blockSize]
				found = binary.Equals(curBlock, testR)
				if found {
					secret = append(secret, byte(i))
					fmt.Printf("%d nth byte is %d %s\n",len(secret),  i, secret)
				}
			}
			if !found {
				/* What happens here is that PKCS7 padding varies depending on
				the number of bytes appended, so once it has discovered one
				padding byte, the next iteration it will be different.
				 */
				break first
			}
			copy(testBlock[0:], testBlock[1:])
		}
	}
	secret = binary.WeakRemovePKCS7Pad(secret)
	fmt.Printf("Got %d bytes:\n%s\n", len(secret), secret)
	if !binary.Equals(secret, target) {
		panic(target)
	}
}
