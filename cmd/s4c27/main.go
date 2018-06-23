package main

import (
	"os"
	"fmt"
	"github.com/adriansr/cryptopals-challenge/util"
	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"strings"
	"github.com/adriansr/cryptopals-challenge/text/ascii"
	"bytes"
	"net/url"
	"github.com/adriansr/cryptopals-challenge/crypto/xor"
)

var origKey = util.RandomBytes(aes.BlockSize)

func encryptWithKeyAsIV(data string, key []byte) []byte {
	bc, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	cbc := crypto.NewCBCBlockMode(key, bc)
	return cbc.Encrypt(strings.NewReader(data))
}

func encrypt(data string) []byte {
	if !ascii.IsValid([]byte(data)) {
		panic(data)
	}
	return encryptWithKeyAsIV(data, origKey)
}

func check(ciphertext []byte) (bool, error) {
	bc, err := aes.NewCipher(origKey)
	if err != nil {
		panic(err)
	}
	cbc := crypto.NewCBCBlockMode(origKey, bc)
	plaintext := cbc.Decrypt(bytes.NewReader(ciphertext))
	if !ascii.IsValid(plaintext) {
		return false, fmt.Errorf("input has invalid characters: %s",
			url.QueryEscape(string(plaintext)))
	}
	return bytes.Contains(plaintext, []byte(";admin=true;")), nil
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		os.Exit(1)
	}

	ciphertext := encrypt("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	isAdmin, err := check(ciphertext)
	if err != nil {
		panic(err)
	}
	if isAdmin {
		panic(isAdmin)
	}
	copy(ciphertext[32:], ciphertext[:16])
	copy(ciphertext[16:32], make([]byte, 16))

	isAdmin, err = check(ciphertext)
	if err == nil {
		panic(err)
	}
	if isAdmin {
		panic(isAdmin)
	}
	fmt.Fprintf(os.Stderr, "got expected error='%v'\n", err)
	msg := err.Error()
	pos := strings.Index(msg, ": ")
	rawS, err := url.QueryUnescape(msg[pos+2:])
	if err != nil {
		panic(err)
	}
	raw := []byte(rawS)
	if len(raw) != len(ciphertext) {
		panic(len(raw))
	}
	xor.XORBlocks(raw[:16], raw[32:])
	rKey := raw[:16]


	isAdmin, err = check(encryptWithKeyAsIV("a;admin=true;bxx", rKey))
	if err != nil {
		panic(err)
	}
	if !isAdmin {
		panic(isAdmin)
	}
	fmt.Fprintf(os.Stderr, "ADMIN!\n")
}
