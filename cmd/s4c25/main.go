package main

import (
	"os"
	"fmt"
	"io/ioutil"
	"github.com/adriansr/cryptopals-challenge/util"
	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"bytes"
	"encoding/binary"
	"crypto/cipher"
)

// Make it more challenging
const MaxEdit = 15

var key = util.RandomBytes(aes.BlockSize)
var nonce = binary.BigEndian.Uint64(util.RandomBytes(8))
var bc cipher.Block

func init() {
	var err error
	bc, err = aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
}
func loadCyphertext(filename string) []byte {
	fHandle, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer fHandle.Close()
	plaintext, err := ioutil.ReadAll(fHandle)
	if err != nil {
		panic(err)
	}

	ciphertext, err := ioutil.ReadAll(crypto.NewCTRStream(bytes.NewReader(plaintext), nonce, bc))
	if len(ciphertext) != len(plaintext) {
		panic(len(ciphertext) - len(plaintext))
	}
	return ciphertext
}

func edit(ciphertext []byte, pos uint64, newData []byte) {
	if uint64(len(newData)) + pos > uint64(len(ciphertext)) {
		panic(555)
	}
	if len(newData) > MaxEdit {
		panic(444)
	}
	nc, err := ioutil.ReadAll(crypto.NewCTRStreamAtPos(pos, bytes.NewReader(newData), nonce, bc))
	if err != nil {
		panic(err)
	}
	copy(ciphertext[pos:], nc)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <file>\n", os.Args[0])
		os.Exit(1)
	}

	ciphertext := loadCyphertext(os.Args[1])
	n := len(ciphertext)
	buf := make([]byte, n)
	copy(buf, ciphertext)
	for i := 0; i < n; i++ {
		rem := n - i
		if rem > MaxEdit {
			rem = MaxEdit
		}
		// It is even simpler: Editing with the ciphertext is equivalent to
		// decrypt. No need to worry about the keystream.
		edit(buf, uint64(i), buf[i:i+rem])
	}
	fmt.Print(string(buf))
}
