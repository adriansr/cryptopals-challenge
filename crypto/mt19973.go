package crypto

import (
	"io"
	"encoding/binary"
	"github.com/adriansr/cryptopals-challenge/crypto/xor"
	"github.com/adriansr/cryptopals-challenge/random"
)

const blockSizeDwords = 64

type MT19937Stream struct {
	mt *random.MT19937
	input io.Reader
	block []byte
	backing []byte
}

func NewMT19937Stream(input io.Reader, mt *random.MT19937) io.Reader {
	s := MT19937Stream{
		mt: mt,
		input: input,
		backing: make([]byte, 4 * blockSizeDwords),
	}
	return &s
}

func (s *MT19937Stream) fillBlock() {
	for i := 0; i < blockSizeDwords; i++ {
		binary.BigEndian.PutUint32(s.backing[i*4:(i*4)+4], s.mt.Next())
	}
	s.block = s.backing
}

func (s *MT19937Stream) Read(buf []byte) (n int, err error) {
	n, err = s.input.Read(buf)
	for i := 0; i < n; {
		if len(s.block) == 0 {
			s.fillBlock()
		}
		avail := n - i
		if avail > len(s.block) {
			avail = len(s.block)
		}
		xor.XORBlocks(buf[i:i+avail], s.block[:avail])
		s.block = s.block[avail:]
		i += avail
	}
	return n, err
}
