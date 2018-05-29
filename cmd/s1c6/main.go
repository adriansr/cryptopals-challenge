package main

import (
	"fmt"
	"os"
	"github.com/adriansr/cryptopals-challenge/binary"
	"bufio"
	"io"
	"encoding/base64"
	"github.com/adriansr/cryptopals-challenge/bruteforce/xor_vigenere"
	"github.com/adriansr/cryptopals-challenge/bruteforce/xor_single"
	"github.com/adriansr/cryptopals-challenge/text/freq_analysis"
	"github.com/adriansr/cryptopals-challenge/terminal"
	"github.com/adriansr/cryptopals-challenge/crypto/xor"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <file>\n", os.Args[0])
		os.Exit(1)
	}

	// check HammingDistance
	if dist := binary.HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")); dist != 37 {
		panic(dist)
	}


	fHandle, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer fHandle.Close()
	reader := bufio.NewReader(fHandle)

	var ciphertext []byte
	var buf []byte
	for {
		if line, isPref, err := reader.ReadLine(); err == nil && !isPref {
			nraw := base64.StdEncoding.DecodedLen(len(line))
			if len(buf) < nraw {
				buf = make([]byte, nraw)
			}
			ndecoded, err := base64.StdEncoding.Decode(buf, line)
			if err != nil {
				panic(err)
			}
			ciphertext = append(ciphertext, buf[:ndecoded]...)
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
	fmt.Fprintf(os.Stderr, "Read %d bytes\n", len(ciphertext))

	sizes := xor_vigenere.GuessKeySizes(ciphertext, 2, 40, 10)
	N := len(ciphertext)

	var bestScore = -1.0
	var bestKey string
	for _, keySize := range sizes {
		key := make([]byte, keySize)
		var score float64
		for keyByte := 0; keyByte < keySize; keyByte ++ {
			partial := make([]byte, 0, keySize + (N / keySize))
			for idx := keyByte; idx < N; idx += keySize {
				partial = append(partial, ciphertext[idx])
			}
			_, pKey, pScore := xor_single.BruteForceXORSingle(partial, freq_analysis.EnglishRelativeFrequencies)
			key[keyByte] = pKey
			score += pScore
		}
		plain := xor.Encrypt(ciphertext, key)
		fmt.Fprintf(os.Stderr, "key '%s' score %f // %s\n", terminal.PrettyASCII(key), score, terminal.PrettyASCII(plain[:50]))
		if score > bestScore {
			bestScore = score
			bestKey = string(key)
		}
	}
	key := []byte(bestKey)
	fmt.Fprintf(os.Stderr, "***\nSelected key '%s' score %f\n***\n", terminal.PrettyASCII(key), bestScore)

	fmt.Print(string(xor.Encrypt(ciphertext, key)))
}
