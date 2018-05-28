package terminal

import "github.com/adriansr/cryptopals/text/ascii"

var (
	redQuestionMark = []byte("\x1b[38;5;1m?\x1b[m")
)

func PrettyASCII(data []byte) string {
	var str []byte
	for _, val := range data {
		if ascii.IsPrint(val) {
			str = append(str, val)
		} else {
			str = append(str, redQuestionMark...)
		}
	}
	return string(str)
}
