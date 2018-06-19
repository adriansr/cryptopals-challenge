package main

import (
	"github.com/adriansr/cryptopals-challenge/random"
)

func main() {
	// use MT19937 as a random generator for our random seconds :)
	target := random.NewMT19937Random()
	cloner := random.NewMT19937Cloner()
	for cloner.Feed(target.Next()) {
	}
	clone := cloner.Get()
	for i := 0; i < 10000; i++ {
		a := target.Next()
		b := clone.Next()
		if a != b {
			panic(i)
		}
	}
}
