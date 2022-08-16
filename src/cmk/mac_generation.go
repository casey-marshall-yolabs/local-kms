package cmk

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"errors"
	"hash"
)

func (k *MacKey) GenerateMac(input []byte, macAlgorithm string) (macResult []byte, err error) {
	key := k.BackingKey

	var h func() hash.Hash
	switch MacAlgorithm(macAlgorithm) {
	case MacAlgorithmHmacSHA224:
		h = sha256.New224
	case MacAlgorithmHmacSHA256:
		h = sha256.New
	case MacAlgorithmHmacSHA384:
		h = sha512.New384
	case MacAlgorithmHmacSHA512:
		h = sha512.New
	default:
		err = errors.New("invalid MAC algorithm")
		return
	}

	mac := hmac.New(h, key[:])
	mac.Write(input)
	macResult = mac.Sum(nil)
	return
}
