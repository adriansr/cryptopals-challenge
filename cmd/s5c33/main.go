package main

import (
	"fmt"
	"os"

	"github.com/adriansr/cryptopals-challenge/crypto/small_num"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"math/big"
	"encoding/hex"
)

const (
	SP = 37
	SG = 2

	P = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020b" +
		"bea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d" +
		"6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a89" +
		"9fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a" +
		"69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c" +
		"354e4abc9804f1746c08ca237327ffffffffffffffff"
	G = "02"
)

func small() {
	a := small_num.NewSmallNumDiffieHellman(SP, SG)
	b := small_num.NewSmallNumDiffieHellman(SP, SG)
	a.Negotiate(b.A)
	b.Negotiate(a.A)

	if a.Key() != b.Key() {
		panic("keys don't match")
	}
	fmt.Printf("Got small key %v\n", a.Key())
}

func decode(s string) *big.Int {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	n := big.Int{}
	n.SetBytes(bytes)
	return &n
}

func large() {
	p := decode(P)
	g := decode(G)
 	a := crypto.NewDiffieHellman(p, g)
 	b := crypto.NewDiffieHellman(p, g)
 	a.Negotiate(b.A)
 	b.Negotiate(a.A)
 	if a.Key().Cmp(b.Key()) != 0 {
 		panic("diff")
	}
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		os.Exit(1)
	}

	small()
	large()

}
