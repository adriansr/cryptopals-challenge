package main

import (
	"os"
	"fmt"
	"encoding/base64"
	"io/ioutil"
	"crypto/aes"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <file>\n", os.Args[0])
		os.Exit(1)
	}

	fHandle, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer fHandle.Close()
	ciphertext, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, fHandle))
	if err != nil {
		panic(err)
	}
	key := []byte("YELLOW SUBMARINE")
	block, err := aes.NewCipher(key)

	plaintext := make([]byte, 0, len(ciphertext))
	buf := make([]byte, aes.BlockSize)
	for o,n := 0, len(ciphertext); o < n; o += aes.BlockSize {
		bs := aes.BlockSize
		if bs > n - o {
			bs = n - o
		}
		block.Decrypt(buf, ciphertext[o:o+bs])
		plaintext = append(plaintext, buf[:bs]...)
	}

	fmt.Printf("%s\n", string(plaintext))
}
