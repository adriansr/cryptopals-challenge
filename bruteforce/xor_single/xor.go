package xor_single

import (
	"github.com/adriansr/cryptopals-challenge/text/freq_analysis"
)

func BruteForceXORSingle(cyphertext []byte, frequencyMap freq_analysis.FrequencyMap) (plaintext []byte, key byte, score float64) {
	N := len(cyphertext)
	buf := make([]byte, N)

	best := struct {
		key   int
		str   []byte
		score float64
	}{}

	for keyInt := 0; keyInt < 256; keyInt++ {

		key := byte(keyInt)

		for idx, value := range cyphertext {
			buf[idx] = value ^ key
		}

		score := freq_analysis.ScoreFrequencies(buf, freq_analysis.EnglishRelativeFrequencies)
		if score > best.score {
			best.score = score
			best.str = make([]byte, N)
			copy(best.str, buf)
			best.key = keyInt
		}
		// fmt.Printf("debug: <<%s>> key=%02X score=%f\n", terminal.PrettyASCII(plaintext), keyInt, score)
	}
	// fmt.Printf("Result: <<%s>> key=%02X score=%f\n", best.str, best.key, best.score)
	return best.str, byte(best.key), best.score
}
