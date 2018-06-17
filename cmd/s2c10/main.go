package main

import (
	"os"
	"fmt"
	"encoding/base64"
	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"bufio"
	"github.com/adriansr/cryptopals-challenge/binary"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <e|d> <file>\n", os.Args[0])
		os.Exit(1)
	}

	fHandle, err := os.Open(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer fHandle.Close()

	key := []byte("YELLOW SUBMARINE")
	cipher, err := aes.NewCipher(key)
	iv := [aes.BlockSize]byte{}

	bm := crypto.NewCBCBlockMode(iv[:], cipher)
	if os.Args[1] == "d" {
		inReader := base64.NewDecoder(base64.StdEncoding, fHandle)
		plaintext := bm.Decrypt(inReader)
		fmt.Printf("%s\n", string(plaintext))
	} else {
		ciphertext := bm.Encrypt(binary.NewPKCS7Reader(bufio.NewReader(fHandle), aes.BlockSize))
		fmt.Printf("%s\n", string(base64.StdEncoding.EncodeToString(ciphertext)))
	}
}
