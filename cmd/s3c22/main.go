package main

import (
	"github.com/adriansr/cryptopals-challenge/random"
	"time"
	"fmt"
)

func main() {
	// use MT19937 as a random generator for our random seconds :)
	actualRnd := random.NewMT19937Random()
	actualRnd.Seed(uint32(time.Now().UnixNano() >> 10))

	victimRnd := random.NewMT19937Random()
	t := uint32(time.Now().Unix())
	victimRnd.Seed(t)
	target := victimRnd.Next()
	t += 40 + (actualRnd.Next() & 0x3ff)

	for xt,limit := t, t - 2000; xt > limit; xt -- {
		if random.NewMT19937Random().Seed(xt).Next() == target {
			fmt.Printf("Original seed was %d\n", xt)
		}
	}
}
