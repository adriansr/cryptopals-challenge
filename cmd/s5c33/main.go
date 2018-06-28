package main

import (
	"fmt"
	"os"

	"github.com/adriansr/cryptopals-challenge/crypto/small_num"
)

const (
	P = 37
	G = 5
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		os.Exit(1)
	}

	a := small_num.NewSmallNumDiffieHellman(P, G)
	b := small_num.NewSmallNumDiffieHellman(P, G)
	a.Negotiate(b.A)
	b.Negotiate(a.A)

	if a.Key() != b.Key() {
		panic("keys don't match")
	}
	fmt.Printf("Got key %v\n", a.Key())
}
