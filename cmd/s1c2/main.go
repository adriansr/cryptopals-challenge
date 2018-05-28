package main

import (
	"os"
	"fmt"
	"encoding/hex"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <hex-string-A> <hex-string-B>\n", os.Args[0])
		os.Exit(1)
	}

	decodedA, err := hex.DecodeString(os.Args[1])
	if err != nil {
		panic(err)
	}

	decodedB, err := hex.DecodeString(os.Args[2])
	if err != nil {
		panic(err)
	}

	if len(decodedA) != len(decodedB) {
		panic("len mismatch")
	}

	for idx := range decodedA {
		decodedA[idx] ^= decodedB[idx]
	}

	fmt.Printf("%s\n", hex.EncodeToString(decodedA))
}



