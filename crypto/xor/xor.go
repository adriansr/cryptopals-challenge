package xor

func Encrypt(plaintext []byte, key []byte) (ciphertext []byte) {
	keyPos, numKey := 0, len(key)
	ciphertext = make([]byte, len(plaintext))
	for idx, plain := range plaintext {
		k := key[keyPos]
		keyPos ++
		if keyPos == numKey {
			keyPos = 0
		}
		ciphertext[idx] = plain ^ k
	}
	return ciphertext
}
