package otp

import (
	"crypto/rand"
	"log"
	"math/big"
)

func cryptoRandSecure(maxNum int) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(maxNum)))
	if err != nil {
		log.Println(err)
	}
	return int(nBig.Int64())
}
