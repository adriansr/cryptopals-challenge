package io_util

import "io"

func Read(input io.Reader, buf []byte) (nread int, err error) {
	var nr int
	for wanted := len(buf); err == nil && nread < wanted; {
		nr, err = input.Read(buf[nread:])
		nread += nr
	}
	return
}
