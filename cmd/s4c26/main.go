package main

import (
	"fmt"
	"os"

	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"strings"
	binary2 "encoding/binary"
	"github.com/adriansr/cryptopals-challenge/util"
	"io/ioutil"
	"github.com/adriansr/cryptopals-challenge/crypto/xor"
	"bytes"
)

const (
	//        .../.../.../...0.../.../.../...1
	prefix = "comment1=cooking%20MCs;userdata="
	sufix = ";comment2=%20like%20a%20pound%20of%20bacon"
	needle = ";admin=true;"
)

var (
	key = util.RandomBytes(aes.BlockSize)
	nonce = binary2.BigEndian.Uint64(util.RandomBytes(8))
)

func cleanup(s string) string {
	d := []byte(s)
	for idx, val := range d {
		switch val {
		case ';', '=': d[idx] = '.'
		}
	}
	return string(d)
}

func encrypt(userData string) []byte {
	data := fmt.Sprintf("%s%s%s", prefix, cleanup(userData), sufix)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	result, err := ioutil.ReadAll(crypto.NewCTRStream(strings.NewReader(data), nonce, cipher))
	if err != nil {
		panic(err)
	}
	return result
}

func checkAdmin(cookie []byte) bool {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	result, err := ioutil.ReadAll(crypto.NewCTRStream(bytes.NewReader(cookie), nonce, cipher))
	if err != nil {
		panic(err)
	}
	return strings.Contains(string(result), needle)
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		os.Exit(1)
	}

	payload := []byte(needle)
	mask := []byte{1,0,0,0,0,0,1,0,0,0,0,1}
	xor.XORBlocks(payload, mask)
	fmt.Fprintf(os.Stderr, "encrypt '%s'\n", string(payload))
	cookie := encrypt(string(payload))
	if checkAdmin(cookie) {
		panic(cookie)
	}
	off, len := len(prefix), len(mask)
	xor.XORBlocks(cookie[off:off+len], mask)
	if !checkAdmin(cookie) {
		panic(false)
	}
	fmt.Fprintf(os.Stderr, "success!\n")
}
