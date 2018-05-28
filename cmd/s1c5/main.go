package main

import (
	"os"
	"fmt"
	"strings"
	"github.com/adriansr/cryptopals/crypto/xor"
	"encoding/hex"
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
