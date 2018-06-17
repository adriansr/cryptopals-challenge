package main

import (
	"os"
	"fmt"
	"github.com/adriansr/cryptopals-challenge/util"
	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/binary"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"bytes"
	"github.com/adriansr/cryptopals-challenge/crypto/xor"
	"encoding/base64"
)

var (
	plaintexts = []string {
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	key = util.RandomBytes(aes.BlockSize)
)

func serverCheck(ciphertext, iv []byte) (bool) {
	cr, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	reader := bytes.NewReader(ciphertext)
	plainPad := crypto.NewCBCBlockMode(iv, cr).Decrypt(reader)
	_, err = binary.RemovePKCS7Pad(plainPad, aes.BlockSize)
	return err == nil
}

func getCookie() (ciphertext []byte, iv []byte) {
	iv = util.RandomBytes(aes.BlockSize)
	b64 := plaintexts[int(util.RandomByte()) % len(plaintexts)]
	plain, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic(err)
	}
	reader := binary.NewPKCS7Reader(bytes.NewReader(plain), aes.BlockSize)
	cr, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return crypto.NewCBCBlockMode(iv, cr).Encrypt(reader), iv
}

func oracleAttackByte(target []byte, known []byte, bs int, oracle func([]byte)bool) byte {
	if len(target) != bs {
		panic("oracleAttack target is not a block")
	}
	if len(known) >= bs {
		panic("too many known bytes")
	}
	nn := len(known)
	idx := bs - nn - 1
	ciphertext := make([]byte, 2*bs)
	copy(ciphertext, util.RandomBytes(bs-nn))
	copy(ciphertext[bs-nn:bs], known)
	copy(ciphertext[bs:], target)
	for i := bs - 1; i > idx; i-- {
		ciphertext[i] ^= byte(nn + 1)
	}
	for i := 0; i < 256; i++ {
		b := byte(i)
		ciphertext[idx] = b
		if ok := oracle(ciphertext); ok {
			// avoid false positive when we get an initial \02\02 by chance
			if nn == 0 {
				ciphertext[idx-1] ++
				ok = oracle(ciphertext)
			}
			if ok {
				return b ^ byte(nn + 1)
			}
		}
	}
	panic("oracle is fucked up")
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		os.Exit(1)
	}

	ciphertext, iv := getCookie()
	oracle := func(ct []byte) bool {
		return serverCheck(ct, iv)
	}
	nBlocks := len(ciphertext) / aes.BlockSize
	var intermediate []byte
	for blockIdx := 0; blockIdx < nBlocks; blockIdx ++ {
		target := ciphertext[blockIdx*aes.BlockSize:(blockIdx+1)*aes.BlockSize]
		var known []byte
		for len(known) < aes.BlockSize {
			r := oracleAttackByte(target, known, aes.BlockSize, oracle)
			known = append([]byte{r}, known...)
		}
		intermediate = append(intermediate, known...)
	}
	plain := make([]byte, len(ciphertext))
	copy(plain, iv)
	copy(plain[aes.BlockSize:], ciphertext)
	xor.XORBlocks(plain, intermediate)
	fmt.Printf("%s\n", plain)
}
