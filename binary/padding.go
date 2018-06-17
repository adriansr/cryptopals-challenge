package binary

import (
	"errors"
	"io"
	"github.com/adriansr/cryptopals-challenge/util"
)

func AddPKCS7Pad(data []byte, blockSize int) []byte {
	n := len(data)
	padBytes := blockSize - (n % blockSize)
	result := make([]byte, n + padBytes)
	copy(result, data)
	for i := n; i < n + padBytes; i++ {
		result[i] = byte(padBytes)
	}
	return result
}

func RemovePKCS7Pad(data []byte, blockSize int) ([]byte, error) {
	n := len(data)
	if n == 0 {
		return nil, errors.New("no data")
	}
	if n % blockSize != 0 {
		return nil, errors.New("data not aligned")
	}
	pad := data[n-1]
	if 0 < int(pad) && int(pad) <= blockSize {
		for i := n-int(pad); i < n-1; i++ {
			if data[i] != pad {
				return nil, errors.New("inconsistent padding")
			}
		}
		return data[:n-int(pad)], nil
	}
	return nil, errors.New("bad padding")
}

// This method is used when leading bytes are extracted, as the extraction method
// cannot work correctly with padding, so its just an unsafe cleanup
func WeakRemovePKCS7Pad(data []byte) []byte {
	n := len(data)
	if n == 0 {
		return nil
	}
	pad := data[n-1]
	if int(pad) < n {
		for i := n-int(pad); i < n-1; i++ {
			if data[i] != pad {
				return data
			}
		}
		return data[:n-int(pad)]
	}
	return data
}

type pkcs7Reader struct {
	reader io.Reader
	blockSize int
	done bool
}

func NewPKCS7Reader(underlying io.Reader, blockSize int) io.Reader {
	reader := pkcs7Reader{
		reader: underlying,
		blockSize: blockSize,
	}
	return &reader
}

func (r *pkcs7Reader) Read(dest []byte) (nr int, err error) {
	if len(dest) != r.blockSize {
		panic("expects to read a block")
	}
	if r.done {
		return 0, io.EOF
	}
	nr, err = util.Read(r.reader, dest)
	if (err == nil || err == io.EOF) && nr < r.blockSize {
		r.done = true
		pad := byte(r.blockSize - nr)
		for i := nr; i < r.blockSize; i++ {
			dest[i] = pad
		}
	}
	return r.blockSize, err
}
