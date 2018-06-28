package digest

import "encoding/binary"

// SHA1("The quick brown fox jumps over the lazy dog")
// gives hexadecimal: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12

// SHA1("The quick brown fox jumps over the lazy cog")
// gives hexadecimal: de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3

// SHA1("")
// gives hexadecimal: da39a3ee5e6b4b0d3255bfef95601890afd80709

const (
	chunkSizeBytes = 64
	internalWords = 80
)

type sha1 struct {
	length uint64
	h      [5]uint32
	buf    []byte
}

func NewSHA1() Digest {
	var s sha1
	s.h[0] = 0x67452301
	s.h[1] = 0xEFCDAB89
	s.h[2] = 0x98BADCFE
	s.h[3] = 0x10325476
	s.h[4] = 0xC3D2E1F0
	return &s
}

func (s *sha1) Write(data []byte) (n int, err error) {
	n = len(data)
	s.length += uint64(n)
	s.buf = append(s.buf, data...)
	for len(s.buf) >= chunkSizeBytes {
		s.hashChunk()
		s.buf = s.buf[chunkSizeBytes:]
	}
	return
}

func (s *sha1) GetDigest() []byte {
	on := len(s.buf)
	n := on + 9
	rem := n & (chunkSizeBytes-1)
	if rem != 0 {
		n += chunkSizeBytes - rem
	}
	state := *s
	state.buf = make([]byte, n)
	copy(state.buf, s.buf)
	state.buf[on] = 0x80
	binary.BigEndian.PutUint64(state.buf[n-8:], state.length * 8)

	for len(state.buf) >= chunkSizeBytes {
		state.hashChunk()
		state.buf = state.buf[chunkSizeBytes:]
	}
	if len(state.buf) != 0 {
		panic(len(state.buf))
	}
	var digest [20]byte
	for i := 0; i < 5; i++ {
		binary.BigEndian.PutUint32(digest[i*4:], state.h[i])
	}
	return digest[:]
}

func (s *sha1) hashChunk() {
	if len(s.buf) < chunkSizeBytes {
		panic(len(s.buf))
	}
	var w [internalWords]uint32
	var i int
	for i = 0; i < chunkSizeBytes / 4; i++ {
		w[i] = binary.BigEndian.Uint32(s.buf[i*4:])
	}
	for ; i<internalWords; i++ {
		wi := w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
		w[i] = (wi << 1) | (wi >> 31)
	}
	a,b,c,d,e := s.h[0], s.h[1], s.h[2], s.h[3], s.h[4]
	var f, k, temp uint32

	var stage uint8
	for i = 0; i < internalWords; i ++ {
		switch stage {
		case 0:
			if i == 19 {
				stage++
			}
			f = (b & c) | ((^b) & d)
			k = 0x5A827999
		case 1:
			if i == 39 {
				stage++
			}
			f = b ^ c ^ d
			k = 0x6ED9EBA1

		case 2:
			if i == 59 {
				stage++
			}
			f = (b & c) | (b & d) | (c & d)
			k = 0x8F1BBCDC
		case 3:
			f = b ^ c ^ d
			k = 0xCA62C1D6

		}
		temp = ((a << 5) | (a >> 27)) + f + e + k + w[i]
		e = d
		d = c
		c = (b << 30) | (b >> 2)
		b = a
		a = temp
	}
	s.h[0] += a
	s.h[1] += b
	s.h[2] += c
	s.h[3] += d
	s.h[4] += e
}
