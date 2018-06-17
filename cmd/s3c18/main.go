package main

import (
	"os"
	"encoding/base64"
	"encoding/hex"
	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"bytes"
	"github.com/adriansr/cryptopals-challenge/util"
	"io"
	"fmt"
	"github.com/adriansr/cryptopals-challenge/terminal"
)

var key = []byte("YELLOW SUBMARINE")
const nonce uint64 = 0

func main() {
	var data []byte
	var err error
	if len(os.Args) == 1 {
		data, err = base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	} else {
		data, err = hex.DecodeString(os.Args[1])
	}
	if err != nil {
		panic(err)
	}
	cb, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ctr := crypto.NewCTRStream(bytes.NewReader(data), nonce, cb)
	buf := make([]byte, 10)
	var out []byte
	for {
		n, err := util.Read(ctr, buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if err != io.EOF {
				panic(err)
			}
			break
		}
	}
	fmt.Println(hex.EncodeToString(out))
	fmt.Printf("<<<%s>>>\n", terminal.PrettyASCII(out))
}
