package main

import (
	"fmt"
	"os"

	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"regexp"
	"strings"
	"encoding/hex"
	"bytes"
	"github.com/adriansr/cryptopals-challenge/terminal"
	"github.com/adriansr/cryptopals-challenge/binary"
	"net/url"
	"strconv"
)


var key = []byte("OLA KE ASE CLABE")

var basicRegexp *regexp.Regexp

func init() {
	var err error
	if basicRegexp, err = regexp.Compile(`^[a-zA-Z._\-0-9]*@[a-zA-Z._\-0-9]*$`); err != nil {
		panic(err)
	}
}

func profileFor(email string, bm crypto.BlockMode) (account string, ciphertext []byte) {
	if !basicRegexp.MatchString(email) {
		return
	}
	sum := 0
	for _, val := range email {
		sum += int(val)
	}
	account = fmt.Sprintf("email=%s&uid=%d&role=user", email, 10 + (sum%10))
	ciphertext = bm.Encrypt(strings.NewReader(account))
	return
}

func login(cookie string) {
	values, err := url.ParseQuery(cookie)
	if err != nil {
		panic(err)
	}
	for _, key := range []string{"email", "uid", "role"} {
		if v, ok := values[key]; ok {
			if len(v) < 1 {
				panic(v)
			}
		} else {
			panic(key)
		}
	}
	sum := 0
	for _, value := range values["email"][0] {
		sum += int(value)
	}
	uid, err := strconv.Atoi(values["uid"][0])
	if err != nil {
		panic(err)
	}
	if  uid != 10 + (sum%10) {
		panic(sum)
	}

	role := values["role"][0]
	switch role {
	case "user", "admin":
		fmt.Printf("User '%s' is %s\n", values["email"][0], role)
	default:
		panic(role)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <signup|login> [data]\n", os.Args[0])
		os.Exit(1)
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	cb := crypto.NewECBBlockMode(cipher)

	if os.Args[1] == "signup" {
		email := os.Args[2]
		plaintext, ciphertext := profileFor(email, cb)
		fmt.Printf("%s\n%s\n", plaintext, hex.EncodeToString(ciphertext))
	} else if os.Args[1] == "login" {
		ciphertext, err := hex.DecodeString(os.Args[2])
		if err != nil {
			panic(err)
		}
		plaintext := binary.RemovePKCS7Pad(cb.Decrypt(bytes.NewReader(ciphertext)))
		fmt.Printf("Attempting '%s'\n", terminal.PrettyASCII(plaintext))
		login(string(plaintext))
	} else {
		panic(os.Args[1])
	}
}
