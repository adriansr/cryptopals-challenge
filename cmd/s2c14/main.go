package main

import (
	"crypto/aes"
	"bytes"
	"fmt"
	"os"

	"github.com/adriansr/cryptopals-challenge/crypto"
	"github.com/adriansr/cryptopals-challenge/util"
	"encoding/base64"
	"github.com/adriansr/cryptopals-challenge/binary"
)


var (
	key = util.RandomBytes(aes.BlockSize)
	targetStr =
		"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
			"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
			"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
			"YnkK"

	target []byte
	leading []byte
)

func init() {
	var err error
	if target, err = base64.StdEncoding.DecodeString(targetStr); err != nil {
		panic(err)
	}
	n := 1 + int(util.RandomByte())
	leading = util.RandomBytes(n)
}

func blindEncrypt(data []byte) []byte {
	cb, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	plaintext := make([]byte, 0, len(data) + len(target) + len(leading))
	plaintext = append(append(append(plaintext, leading...), data...), target...)

	bm := crypto.NewECBBlockMode(cb)
	return bm.Encrypt(bytes.NewReader(plaintext))
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

	// Find the first block that lays completely under our control
	// Append 3 null blocks, 2 should be repeated
	empty := make([]byte, 3 * blockSize)
	output := fn(empty)
	inBlock := -1
	for idx := 0; (idx+2)*blockSize <= len(output); idx ++ {
		if binary.Equals(output[idx*blockSize:(idx+1)*blockSize], output[(idx+1)*blockSize:(idx+2)*blockSize]) {
			fmt.Fprintf(os.Stderr,"Found repetition starting at block #%d\n", idx)
			inBlock = idx
			break
		}
	}
	if inBlock == -1 {
		// Repeated block not found
		panic(inBlock)
	}
	// Get the encrypted null-block
	kZero := make([]byte, blockSize)
	copy(kZero, output[inBlock*blockSize:(inBlock+1)*blockSize])

	// Guess pad required to align our injected data to block boundary
	// that is, (len(leading) % blockSize)
	minLenForFullBlock := 2*blockSize
	for len := 2 * blockSize; len > 0; len -- {
		output = fn(empty[:len])
		if binary.Equals(kZero, output[inBlock*blockSize:(inBlock+1)*blockSize]) {
			minLenForFullBlock = len
		}
	}
	if minLenForFullBlock < blockSize || minLenForFullBlock >= 2*blockSize {
		panic(minLenForFullBlock)
	}
	lPad := minLenForFullBlock % blockSize
	fmt.Fprintf(os.Stderr, "mlfb=%d lpad=%d\n", minLenForFullBlock, lPad)


	numBlocks := fn.BlindLength() / blockSize
	testBlock := make([]byte, blockSize + lPad)
	var secret []byte

first:
	for nBlock := inBlock; nBlock <= numBlocks; nBlock ++ {
		for pad := lPad + blockSize - 1; pad >= lPad; pad-- {
			curBlock := fn(empty[:pad])[nBlock*blockSize:(nBlock+1)*blockSize]
			found := false
			var testR []byte
			for i := 0; !found && i < 256; i++ {
				testBlock[lPad + blockSize-1] = byte(i)
				testR = fn(testBlock)[inBlock*blockSize:(inBlock+1)*blockSize]
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
	secret = binary.RemovePKCS7Pad(secret)
	fmt.Printf("Got %d bytes:\n%s\n", len(secret), secret)
	if !binary.Equals(secret, target) {
		panic(target)
	}
}
