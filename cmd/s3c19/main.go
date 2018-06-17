package main

import (
	"os"
	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"github.com/adriansr/cryptopals-challenge/util"
	"fmt"
	"encoding/base64"
	"strings"
	"github.com/adriansr/cryptopals-challenge/bruteforce/xor_single"
	"github.com/adriansr/cryptopals-challenge/text/freq_analysis"
	"github.com/adriansr/cryptopals-challenge/crypto/xor"
	"github.com/adriansr/cryptopals-challenge/terminal"
)


const Nonce uint64 = 0

var (
	key = util.RandomBytes(aes.BlockSize)

	plaintexts = []string {
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	}
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		os.Exit(1)
	}
	cb, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertexts := make([][]byte, len(plaintexts))
	for idx, plainb64 := range plaintexts {
		ctr := crypto.NewCTRStream(
			base64.NewDecoder(base64.StdEncoding, strings.NewReader(plainb64)),
			Nonce,
			cb)
		ciphertexts[idx] = make([]byte, base64.StdEncoding.DecodedLen(len(plainb64)))
		util.Read(ctr, ciphertexts[idx])
	}

	var keystream []byte
	for idx := 0; ; idx ++ {
		var xorct []byte
		for _, ct := range ciphertexts {
			if idx < len(ct) {
				xorct = append(xorct, ct[idx])
			}
		}
		if len(xorct) == 0 {
			break
		}
		_, keyByte, score := xor_single.BruteForceXORSingle(xorct, freq_analysis.EnglishRelativeFrequencies)
		keystream = append(keystream, keyByte)
		fmt.Fprintf(os.Stderr, "Got key byte #%d %02x score %v\n", idx, keyByte, score)
	}

	nk := len(keystream)
	for idx, cip := range ciphertexts {
		n := len(cip)
		if nk < n {
			n = nk
		}
		xor.XORBlocks(cip[:n], keystream[:n])
		fmt.Printf("[%d] = <<<%s>>>\n", idx, terminal.PrettyASCII(cip))
	}
}
