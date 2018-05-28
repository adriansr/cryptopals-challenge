package main

import (
	"os"
	"fmt"
	"encoding/hex"
	"github.com/adriansr/cryptopals/text/freq_analysis"
	"github.com/adriansr/cryptopals/terminal"
	"github.com/adriansr/cryptopals/bruteforce/xor_single"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <hex-string>\n", os.Args[0])
		os.Exit(1)
	}

	cyphertext, err := hex.DecodeString(os.Args[1])
	if err != nil {
		panic(err)
	}

	plaintext, key, score := xor_single.BruteForceXORSingle(cyphertext, freq_analysis.EnglishRelativeFrequencies)
	fmt.Printf("Result: <<%s>> key=%02X score=%f\n", terminal.PrettyASCII(plaintext), key, score)
}



