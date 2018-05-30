package binary

func PKCS7Pad(data []byte, length int) []byte {
	n := len(data)
	padBytes := length - n
	if padBytes < 0 {
		panic(padBytes)
	}
	result := make([]byte, length)
	copy(result, data)
	for i := n; i < length; i++ {
		result[i] = byte(padBytes)
	}
	return result
}
