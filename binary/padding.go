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

func RemovePKCS7Pad(data []byte) []byte {
	n := len(data)
	if n == 0 {
		return nil
	}
	pad := data[n-1]
	if int(pad) < n {
		for i := n-int(pad); i < n-1; i++ {
			if data[i] != pad {
				return data
			}
		}
		return data[:n-int(pad)]
	}
	return data
}
