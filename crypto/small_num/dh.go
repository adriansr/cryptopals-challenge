package small_num

import (
	"encoding/binary"
	"github.com/adriansr/cryptopals-challenge/util"
	"math/big"
)

type SmallDH struct {
	p, g, a, A, k uint32
	kSet bool
}

func NewSmallNumDiffieHellman(p, g uint32) *SmallDH {
	dh := SmallDH {
		p: p,
		g: g,
	}
	rnd := binary.BigEndian.Uint32(util.RandomBytes(4))
	dh.a = rnd % dh.p
	dh.A = Modexp(dh.g, dh.a, dh.p)
	return &dh
}

func (dh *SmallDH) Negotiate(B uint32) {
	dh.k = Modexp(B, dh.a, dh.p)
	dh.kSet = true
}

func (dh *SmallDH) Key() uint32 {
	if !dh.kSet {
		panic("key not set")
	}
	return dh.k
}

func Modexp(n, e, m uint32) (r uint32) {
	// TODO
	mm := big.NewInt(int64(m))
	nn := big.NewInt(int64(n))
	ee := big.NewInt(int64(e))
	rr := big.NewInt(0)
	rr.Exp(nn, ee, mm)
	return uint32(rr.Uint64())
}

