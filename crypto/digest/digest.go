package digest

import "io"

type Digest interface {
	io.Writer
	GetDigest() []byte
}
