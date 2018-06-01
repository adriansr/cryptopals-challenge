package util

import "crypto/rand"

func RandomBytes(count int) (bytes []byte) {
	bytes = make([]byte, count)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return bytes
}

func RandomByte() byte {
	var buf [1]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(err)
	}
	return buf[0]
}
