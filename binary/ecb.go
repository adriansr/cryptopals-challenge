package binary

func ECBRepeatedBlockCount(ciphertext []byte, blockSize int) (count int, blocks int) {
	n := len(ciphertext)
	seen := make(map[string]struct{})
	var placeholder = struct{}{}
	for o := 0; o+blockSize < n; o+=blockSize {
		seen[string(ciphertext[o:o+blockSize])] = placeholder
	}
	blocks = n / blockSize
	return blocks - len(seen), blocks
}
