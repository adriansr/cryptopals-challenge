package main

import (
	"os"
	"fmt"
	"encoding/hex"
	"encoding/base64"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <hex-string>\n", os.Args[0])
		os.Exit(1)
	}

	decoded, err := hex.DecodeString(os.Args[1])
	if err != nil {
		panic(err)
	}

	base64 := base64.StdEncoding.EncodeToString(decoded)
	fmt.Printf("%s\n", base64)
}



