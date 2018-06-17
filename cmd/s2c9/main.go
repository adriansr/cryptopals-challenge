package main

import (
	"fmt"
	"os"

	"github.com/adriansr/cryptopals-challenge/binary"
	"strconv"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <plaintext> <length>\n", os.Args[0])
		os.Exit(1)
	}

	plaintext := []byte(os.Args[1])
	length, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	padded := binary.AddPKCS7Pad(plaintext, length)
	fmt.Printf("%v\n", padded)
}
