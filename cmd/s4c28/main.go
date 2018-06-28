package main

import (
	"fmt"
	"os"

	"github.com/adriansr/cryptopals-challenge/crypto/digest"
	"io"
	"encoding/hex"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <key> <files...>\n", os.Args[0])
		os.Exit(1)
	}

	const BufSize = 4096
	var bufMem [BufSize]byte
	buf := bufMem[:]
	for i := 2; i < len(os.Args); i++ {
		sha1mac := digest.NewMac([]byte(os.Args[1]), digest.NewSHA1())
		f, err := os.Open(os.Args[i])
		if err != nil {
			panic(err)
		}
		IO: for {
			n, err := f.Read(buf)
			switch err {
			case nil:
			case io.EOF:
				break IO
			default:
				panic(err)
			}
			if n > 0 {
				sha1mac.Write(buf[:n])
			}
		}
		fmt.Println(hex.EncodeToString(sha1mac.GetDigest()))
	}
}
