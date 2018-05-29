package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/adriansr/cryptopals-challenge/binary"
	"crypto/aes"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <file>\n", os.Args[0])
		os.Exit(1)
	}

	fHandle, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer fHandle.Close()
	reader := bufio.NewReader(fHandle)

	var lines [][]byte
	for {
		if line, isPref, err := reader.ReadLine(); err == nil && !isPref {
			decoded, err := hex.DecodeString(string(line))
			if err != nil {
				panic(err)
			}
			lines = append(lines, decoded)
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

	var bestIdx int = -1
	var bestScore float64 = -1

	for idx, line := range lines {
		reps, total := binary.ECBRepeatedBlockCount(line, aes.BlockSize)
		score := float64(reps) / float64(total)
		if score > bestScore {
			bestScore = score
			bestIdx = idx
		}
	}

	//cx, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	//buf := make([]byte, aes.BlockSize)
	//cx.Decrypt(buf, lines[bestIdx][:aes.BlockSize])
	//fmt.Printf("Best: [%d] <<%s>> score=%d\n", bestIdx, terminal.PrettyASCII(buf), bestScore)

	fmt.Printf("Best: [%d] <<%s>> score=%f\n", bestIdx, hex.EncodeToString(lines[bestIdx][:aes.BlockSize]), bestScore)
}
