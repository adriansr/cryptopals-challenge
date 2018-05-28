package main

import (
	"os"
	"fmt"
	"encoding/hex"
	"bufio"
	"io"
	"github.com/adriansr/cryptopals/text/ascii"
	"github.com/adriansr/cryptopals/terminal"
	"github.com/adriansr/cryptopals/bruteforce/xor_single"
	"github.com/adriansr/cryptopals/text/freq_analysis"
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

	var best []byte
	var bestScore float64

	for idx,line := range lines {
		if ascii.ChangedBitMask(line) & 0x80 == 0 {
			//fmt.Printf("Not changed line %d: %s\n", idx, terminal.PrettyASCII(line))
			plaintext, key, score := xor_single.BruteForceXORSingle(line, freq_analysis.EnglishRelativeFrequencies)
			fmt.Printf("Line %d: <<%s>> key=%02X score=%f\n", idx, terminal.PrettyASCII(plaintext), key, score)
			if score > bestScore {
				bestScore = score
				best = plaintext
			}
		}
	}

	fmt.Printf("Best: <<%s>> score=%f\n", terminal.PrettyASCII(best), bestScore)
}
