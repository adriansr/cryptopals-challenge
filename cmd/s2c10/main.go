package main

import (
	"os"
	"fmt"
	"encoding/base64"
	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"bufio"
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

	if os.Args[1] == "d" {
		inReader := base64.NewDecoder(base64.StdEncoding, fHandle)
		plaintext := crypto.CBCDecrypt(inReader, iv[:], cipher)
		fmt.Printf("%s\n", string(plaintext))
	} else {
		ciphertext := crypto.CBCEncrypt(bufio.NewReader(fHandle), iv[:], cipher)
		fmt.Printf("%s\n", string(base64.StdEncoding.EncodeToString(ciphertext)))
	}
}
