package main

import (
	"os"
	"fmt"
	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"github.com/adriansr/cryptopals-challenge/util"
	"bytes"
	"github.com/adriansr/cryptopals-challenge/binary"
)

func randomEncrypt(data []byte) (ct []byte, isECB bool) {
	cb, err := aes.NewCipher(util.RandomBytes(aes.BlockSize))
	if err != nil {
		panic(err)
	}
	plaintext := bytes.NewReader(append(
		append(util.RandomBytes(5 + int(util.RandomByte()%5)),
			data...),
		util.RandomBytes(5 + int(util.RandomByte()%5))...))

	var bm crypto.BlockMode
	if util.RandomByte() & 1 == 0 {
		iv := util.RandomBytes(aes.BlockSize)
		bm = crypto.NewCBCBlockMode(iv, cb)
	} else {
		bm = crypto.NewECBBlockMode(cb)
		isECB = true
	}
	return bm.Encrypt(plaintext), isECB
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		os.Exit(1)
	}

	plaintext := make([]byte, aes.BlockSize * 4)
	ciphertext, isECB := randomEncrypt(plaintext)
	repeated, _ := binary.ECBRepeatedBlockCount(ciphertext, aes.BlockSize)
	guess := repeated > 1
	match := isECB == guess
	if match {
		fmt.Printf("ok %d %v\n", repeated, guess)
	} else {
		fmt.Printf("FAIL %d %v\n", repeated, guess)
		os.Exit(33)
	}
}
