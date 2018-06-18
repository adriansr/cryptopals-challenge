package main

import (
	"os"
	"fmt"
	"strconv"
	"github.com/adriansr/cryptopals-challenge/random"
)

func main() {
	NA := len(os.Args)
	if NA != 2 && NA != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <count> [seed]\n", os.Args[0])
		os.Exit(1)
	}

	count, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}

	r := random.NewMT19937Random()

	if NA == 3 {
		seed, err := strconv.ParseUint(os.Args[2], 16, 32)
		if err != nil {
			panic(err)
		}
		r.Seed(uint32(seed))
	}

	known := make(map[uint32]struct{})

	for i := 0; i < count; i++ {
		val := r.Next()
		rep := ""
		if _, ok := known[val]; ok {
			rep = " *** REPEATED ***"
		}
		known[val] = struct{}{}
		fmt.Printf("%08x (#%d)%s\n", val, i, rep)
	}
}
