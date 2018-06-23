package main

import (
	"github.com/adriansr/cryptopals-challenge/random"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"bytes"
	"io"
	"github.com/adriansr/cryptopals-challenge/util"
	util_binary "github.com/adriansr/cryptopals-challenge/binary"
	"encoding/binary"
	"fmt"
	"os"
)

const NumKnown = 14

func read4(stream io.Reader, buf []byte) {
	n, err := stream.Read(buf)
	if err != nil {
		panic(err)
	}
	if n != 4 {
		panic(n)
	}
}

func mt19937crypt(key uint16, data []byte) (res []byte) {
	gen := random.NewMT19937Random().Seed(uint32(key))
	n := len(data)
	res = make([]byte, n)
	stream := crypto.NewMT19937Stream(bytes.NewReader(data), gen)
	nread, err := stream.Read(res)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if nread != n {
		panic(nread)
	}
	return res
}

func getKnownPlaintext() (res []byte) {
	res = make([]byte, NumKnown)
	for i := 0; i < NumKnown; i++ {
		res[i] = byte('A')
	}
	return res
}

func getRandomPrefix() []byte {
	nr := 1 + int(util.RandomByte())
	return util.RandomBytes(nr)
}

func main() {
	knownPt := getKnownPlaintext()
	payload := append(getRandomPrefix(), knownPt...)
	secretKey := binary.BigEndian.Uint16(util.RandomBytes(2))
	cyphertext := mt19937crypt(secretKey, payload)
	knownOffset := len(cyphertext) - NumKnown
	// bruteforce
	buf := make([]byte, len(cyphertext))
	copy(buf[knownOffset:], knownPt)
	foundKey := -1
	for key := 0; key <= 0xFFFF; key++ {
		res := mt19937crypt(uint16(key), buf)
		if util_binary.Equals(res[knownOffset:], cyphertext[knownOffset:]) {
			if foundKey != -1 {
				panic(foundKey)
			}
			foundKey = key
		}
	}
	if foundKey == -1 {
		panic(foundKey)
	}
	fmt.Fprintf(os.Stderr, "key=%d found=%d\n", secretKey, foundKey)

	/*
	Original solution, didn't read the requirements.
	This breaks the crypto by encrypting a known plaintext and cloning
	the PRNG from the keystream
	---
	empty := make([]byte, random.MT19937_N * 4)
	empty = append(empty, []byte("HOLA")...)
	stream := crypto.NewMT19937Stream(bytes.NewReader(empty), gen)
	cloner := random.NewMT19937Cloner()
	var buf [4]byte
	for feeding := true; feeding; feeding = cloner.Feed(binary.BigEndian.Uint32(buf[:])) {
		read4(stream, buf[:])
	}

	clone := cloner.Get()
	var key [4]byte
	binary.BigEndian.PutUint32(key[:], clone.Next())
	read4(stream, buf[:])
	xor.XORBlocks(buf[:], key[:])
	msg := string(buf[:])
	if msg != "HOLA" {
		panic(msg)
	}
	*/
}
