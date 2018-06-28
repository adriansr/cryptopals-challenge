package digest

func NewMac(key []byte, digest Digest) Digest {
	digest.Write(key)
	return digest
}
