package random

const (
	w, n, m, r uint32 = 32, 624, 397, 31
	a uint32 = 0x9908B0DF
	u, d uint32 = 11, 0xFFFFFFFF
	s, b uint32 = 7, 0x9D2C5680
	t, c uint32 = 15, 0xEFC60000
	l, f uint32 = 18, 1812433253
	DefaultSeed uint32 = 5489
	lowerMask uint32 = (1 << r) - 1
	upperMask uint32 = (^lowerMask) & ((1 << w) - 1)
)

type MT19937 struct {
	mt [n] uint32
	index  uint32

}

func NewMT19937Random() *MT19937 {
	r := MT19937{
		index: n+1,
	}
	return &r
}

func (mt *MT19937) Seed(s uint32) *MT19937 {
	mt.index = n
	mt.mt[0] = s
	for i := uint32(1); i < n; i++ {
		s = f * (s ^ (s >> (w-2))) + i
		mt.mt[i] = s
	}
	return mt
}

func (mt *MT19937) Next() uint32 {
	if mt.index >= n {
		if mt.index > n {
			mt.Seed(DefaultSeed)
		}
		mt.twist()
	}
	y := mt.mt[mt.index]
	y ^= y >> u
	y ^= (y << s) & b
	y ^= (y << t) & c
	y ^= y >> l

	mt.index ++
	return y
}

func (mt *MT19937) twist() {
	for i := uint32(0); i < n; i++ {
		x := (mt.mt[i] & upperMask) + (mt.mt[(i+1) % n] & lowerMask)
		xa := x >> 1
		if x & 1 != 0 {
			xa = xa ^ a
		}
		mt.mt[i] = mt.mt[(i + m) % n] ^ xa
	}
	mt.index = 0
}
