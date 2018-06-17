package main
// Same approach I used in c19, so same code

import (
	"os"
	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"github.com/adriansr/cryptopals-challenge/util"
	"fmt"
	"encoding/base64"
	"strings"
	"github.com/adriansr/cryptopals-challenge/bruteforce/xor_single"
	"github.com/adriansr/cryptopals-challenge/text/freq_analysis"
	"github.com/adriansr/cryptopals-challenge/crypto/xor"
	"github.com/adriansr/cryptopals-challenge/terminal"
	"io"
	"bufio"
)


const Nonce uint64 = 0

var (
	key = util.RandomBytes(aes.BlockSize)
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <file>\n", os.Args[0])
		os.Exit(1)
	}

	cb, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var plaintexts []string
	fHandle, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer fHandle.Close()
	reader := bufio.NewReader(fHandle)

	for {
		if line, isPref, err := reader.ReadLine(); err == nil && !isPref {
			plaintexts = append(plaintexts, string(line))

		} else {
			if isPref {
				panic(isPref)
			}
			if err == io.EOF {
				break
			}
			panic(err)
		}
	}

	ciphertexts := make([][]byte, len(plaintexts))
	for idx, plainb64 := range plaintexts {
		ctr := crypto.NewCTRStream(
			base64.NewDecoder(base64.StdEncoding, strings.NewReader(plainb64)),
			Nonce,
			cb)
		ciphertexts[idx] = make([]byte, base64.StdEncoding.DecodedLen(len(plainb64)))
		util.Read(ctr, ciphertexts[idx])
	}

	var keystream []byte
	for idx := 0; ; idx ++ {
		var xorct []byte
		for _, ct := range ciphertexts {
			if idx < len(ct) {
				xorct = append(xorct, ct[idx])
			}
		}
		if len(xorct) == 0 {
			break
		}
		_, keyByte, score := xor_single.BruteForceXORSingle(xorct, freq_analysis.EnglishRelativeFrequencies)
		keystream = append(keystream, keyByte)
		fmt.Fprintf(os.Stderr, "Got key byte #%d %02x score %v\n", idx, keyByte, score)
	}

	nk := len(keystream)
	for idx, cip := range ciphertexts {
		n := len(cip)
		if nk < n {
			n = nk
		}
		xor.XORBlocks(cip[:n], keystream[:n])
		fmt.Printf("[%d] = <<<%s>>>\n", idx, terminal.PrettyASCII(cip))
	}
}
