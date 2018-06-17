package main

import (
	"fmt"
	"os"

	"github.com/adriansr/cryptopals-challenge/binary"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		os.Exit(1)
	}

	for idx, data := range [][2]string {
		{"ICE ICE BABY\x04\x04\x04\x04", "ICE ICE BABY"},
		{"ICE ICE BABY\x05\x05\x05\x05", "ICE ICE BABY\x05\x05\x05\x05"},
		{"ICE ICE BABY\x01\x02\x03\x04", "ICE ICE BABY\x01\x02\x03\x04"},
	} {
		res := binary.RemovePKCS7Pad([]byte(data[0]))
		if !binary.Equals(res, []byte(data[1])) {
			fmt.Fprintf(os.Stderr, "Failure at #%d\n", idx)
		}
	}
}
