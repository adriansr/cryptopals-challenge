package crypto

import (
	"crypto/cipher"
	"io"
	"encoding/binary"
	"github.com/adriansr/cryptopals-challenge/crypto/xor"
)

type CTRStream struct {
	cb cipher.Block
	input io.Reader
	nonce uint64
	counter uint64
	block []byte
	backing []byte
}

func NewCTRStream(input io.Reader, nonce uint64, cipher cipher.Block) io.Reader {
	ctr := CTRStream{
		cb: cipher,
		input: input,
		nonce: nonce,
		counter: 0,
		backing: make([]byte, cipher.BlockSize()),
	}
	return &ctr
}

func (ctr *CTRStream) Read(buf []byte) (n int, err error) {
	n, err = ctr.input.Read(buf)
	for i := 0; i < n; {
		if len(ctr.block) == 0 {
			binary.LittleEndian.PutUint64(ctr.backing[:8], ctr.nonce)
			binary.LittleEndian.PutUint64(ctr.backing[len(ctr.backing)-8:], ctr.counter)
			ctr.counter ++
			ctr.cb.Encrypt(ctr.backing, ctr.backing)
			ctr.block = ctr.backing
		}
		avail := n - i
		if avail > len(ctr.block) {
			avail = len(ctr.block)
		}
		xor.XORBlocks(buf[i:i+avail], ctr.block[:avail])
		ctr.block = ctr.block[avail:]
		i += avail
	}
	return n, err
}


