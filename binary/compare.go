package binary

func Equals(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for idx, value := range a {
		if value != b[idx] {
			return false
		}
	}
	return true
}
