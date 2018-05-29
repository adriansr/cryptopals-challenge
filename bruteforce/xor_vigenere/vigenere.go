package xor_vigenere

import (
	"fmt"
	"github.com/adriansr/cryptopals-challenge/binary"
	"sort"
	"os"
)

// GuessKeySizes takes the ciphertext and returns the most probable
// key sizes of length between min and max
func GuessKeySizes(ciphertext []byte, min, max, count int) (result []int) {
	n := len(ciphertext)
	if n < 4 * max {
		panic(fmt.Errorf("input data len=%d too small to guess key size %d", n, max))
	}
	type score struct {
		len int
		score float64
	}
	scores := make([]score, max - min + 1)
	for size, i := min, 0; size <= max; size++ {
		dist := binary.HammingDistance(ciphertext[:size], ciphertext[size:2*size]) +
			binary.HammingDistance(ciphertext[2*size:3*size], ciphertext[3*size:4*size])
		scores[i].len = size
		scores[i].score = float64(dist) / float64(size * 2)
		i ++
	}
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score < scores[j].score
	})
	cc := max - min + 1
	if count < cc {
		cc = count
	}
	result = make([]int, cc)
	for i := 0; i < cc; i++ {
		fmt.Fprintf(os.Stderr, "Debug: Len %d score %f\n", scores[i].len, scores[i].score)
		result[i] = scores[i].len
	}
	return result
}
