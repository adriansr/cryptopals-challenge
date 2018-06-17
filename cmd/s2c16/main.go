package main
//$ ./main encode 'xxxxxxxxxxxxxxxx:admin<true:'
//880352ba80593804e240e7926d6659964fdf18889e7187d6ed4bb7a3d07bb0e989f45c07338fd9ea775fb0ca6478db908bfe17f01b5f0e2a6f436b44ff361e14576c47afec073da35253b0905cb4c96011757c760e884709f9aed107bbd2f711720f5c0604dbf99671b1761ce1481b95
//
// Toggle the equivalent bits in the prev block
//
//$ ./main decode 880352ba80593804e240e7926d6659964fdf18889e7187d6ed4bb7a3d07bb0e988f45c07338fd8ea775fb0cb6478db908bfe17f01b5f0e2a6f436b44ff361e14576c47afec073da35253b0905cb4c96011757c760e884709f9aed107bbd2f711720f5c0604dbf99671b1761ce1481b95
//comment1=cooking%20MCs;userdata=P????????(W?4?x?;admin=true;;comment2=%20like%20a%20pound%20of%20bacon
//ADMIN!
import (
	"fmt"
	"os"

	"crypto/aes"
	"github.com/adriansr/cryptopals-challenge/crypto"
	"strings"
	"encoding/hex"
	"github.com/adriansr/cryptopals-challenge/terminal"
	"github.com/adriansr/cryptopals-challenge/binary"
)

const (
	//        .../.../.../...0.../.../.../...1
	prefix = "comment1=cooking%20MCs;userdata="
	sufix = ";comment2=%20like%20a%20pound%20of%20bacon"
	needle = ";admin=true;"
)

var (
	key = []byte("YELLOW SUBMARINE")
	iv =  []byte("INITIALIZE THIS!")
)

func cleanup(s string) string {
	d := []byte(s)
	for idx, val := range d {
		switch val {
		case ';', '=': d[idx] = '.'
		}
	}
	return string(d)
}

func encrypt(userData string) string {
	data := fmt.Sprintf("%s%s%s", prefix, cleanup(userData), sufix)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(crypto.NewCBCBlockMode(iv, cipher).Encrypt(binary.NewPKCS7Reader(strings.NewReader(data), aes.BlockSize)))
}

func decrypt(hexPayload string) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	plain, err := binary.RemovePKCS7Pad(crypto.NewCBCBlockMode(iv, cipher).Decrypt(hex.NewDecoder(strings.NewReader(hexPayload))), aes.BlockSize)
	if err != nil {
		panic(err)
	}
	return plain
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s encode|decode <data>\n", os.Args[0])
		os.Exit(1)
	}

	switch os.Args[1] {
	case "encode":
		fmt.Printf("%s\n", encrypt(os.Args[2]))

	case "decode":
		res := terminal.PrettyASCII(decrypt(os.Args[2]))
		fmt.Printf("%s\n", res)
		if strings.Contains(res, needle) {
			fmt.Printf("ADMIN!\n")
		}
	default:
		panic(os.Args[1])
	}
}
