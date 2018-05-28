package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/adriansr/cryptopals-challenge/crypto/xor"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <key> <string>...\n", os.Args[0])
		os.Exit(1)
	}

	key := []byte(os.Args[1])
	plaintext := []byte(strings.Join(os.Args[2:], " "))

	ciphertext := xor.Encrypt(plaintext, key)
	fmt.Printf("%s\n", hex.EncodeToString(ciphertext))
}
