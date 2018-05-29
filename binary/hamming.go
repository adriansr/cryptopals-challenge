package binary

import (
	"fmt"
	"math/bits"
)

var popCount [256]int

func init() {
	for i := range popCount {
		popCount[i] = bits.OnesCount8(uint8(i))
	}
}

func HammingDistance(a []byte, b []byte) (dist int) {
	n := len(a)
	if len(b) != n {
		panic(fmt.Sprintf("Lengths differ: %d vs %d", n, len(b)))
	}
	for i, ba := range a {
		dist += popCount[ba ^ b[i]]
	}
	return dist
}
