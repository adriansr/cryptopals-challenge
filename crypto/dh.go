package crypto

import (
	"github.com/adriansr/cryptopals-challenge/util"
	"math/big"
	"fmt"
	"os"
)

type DH struct {
	p, g, a, A, k *big.Int
	kSet bool
}

func NewDiffieHellman(p, g *big.Int) *DH {
	dh := DH {
		p: p,
		g: g,
		a: &big.Int{},
		A: &big.Int{},
		k: &big.Int{},
	}

	rnd := &big.Int{}
	nbits := p.BitLen()
	if rem := nbits & 0x7; rem != 0 {
		nbits += 8 - rem
	}
	fmt.Fprintf(os.Stderr, "bits: %d\n", nbits)
	rnd.SetBytes(util.RandomBytes(nbits/8))
	dh.a.Mod(rnd, dh.p)
	dh.A.Exp(dh.g, dh.a, dh.p)
	return &dh
}

func (dh *DH) Negotiate(B *big.Int) {
	dh.k.Exp(B, dh.a, dh.p)
	dh.kSet = true
}

func (dh *DH) Key() *big.Int {
	if !dh.kSet {
		panic("key not set")
	}
	return dh.k
}
