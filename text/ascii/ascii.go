package ascii

// IsString checks if the given string contains only ASCII characters
func IsString(bytes []byte) bool {
	for _, b := range bytes {
		if b & 0x80 != 0 {
			return false
		}
	}
	return true
}

func IsPrint(b byte) bool {
	// Shamelessly copied from strconv.IsPrint ...
	if 0x20 <= b && b <= 0x7E {
		return true
	}
	//return b >= 0xA1 && b != 0xAD
	return false
}

func ChangedBitMask(data []byte) byte {
	N, mask, first := len(data), byte(0), data[0]
	for i := 1; i < N; i++ {
		mask |= first ^ data[i]
	}
	return mask
}
