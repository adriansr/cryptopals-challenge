package main

import (
	"fmt"
	"os"

	"github.com/adriansr/cryptopals-challenge/util"
	"github.com/adriansr/cryptopals-challenge/crypto/digest"
	"github.com/adriansr/cryptopals-challenge/binary"
	"strings"
	binary2 "encoding/binary"
	"net/url"
	"encoding/hex"
)

const (
	Msg   = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	Admin = ";admin=true;"
)

var secretKey []byte

func init() {
	secretKey = util.RandomBytes(1 + int(util.RandomByte()&0x1f))
}

func getCookie() (data string, mac []byte) {
	digest := digest.NewMac(secretKey, digest.NewSHA1())
	digest.Write([]byte(Msg))
	return Msg, digest.GetDigest()
}

func validate(data string, mac []byte) (bool, bool) {
	digest := digest.NewMac(secretKey, digest.NewSHA1())
	digest.Write([]byte(data))
	r := digest.GetDigest()
	v, a := binary.Equals(r, mac), strings.Contains(data, Admin)
	return v, a && v
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		os.Exit(1)
	}

	cookie, hash := getCookie()
	valid, isAdmin := validate(cookie, hash)
	if !valid || isAdmin {
		panic(!valid)
	}

	for guessKeyLen := 1; guessKeyLen < 64; guessKeyLen ++ {

		o := len(cookie)
		n := o + 9
		rem := (n + guessKeyLen) & 0x3f
		if rem != 0 {
			n += 0x40 - rem
		}
		msg := make([]byte, n)
		copy(msg, []byte(cookie))
		msg[o] = 0x80
		msg = append(msg, []byte(Admin)...)

		binary2.BigEndian.PutUint64(msg[n-8:], uint64((guessKeyLen + o) * 8))
		sha := digest.NewResumedSHA1(uint64(n + guessKeyLen), hash)
		sha.Write([]byte(Admin))
		newMac := sha.GetDigest()

		valid, isAdmin = validate(string(msg), newMac)
		fmt.Fprintf(os.Stderr, "Try %d valid=%v admin=%v - %s '%s'\n",
			guessKeyLen, valid, isAdmin, hex.EncodeToString(newMac),
			url.QueryEscape(string(msg)))
		if valid {
			break
		}
	}
	if !valid {
		panic(valid)
	}
	if !isAdmin {
		panic(isAdmin)
	}
}
