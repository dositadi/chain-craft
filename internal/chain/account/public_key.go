package account

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
)

var (
	ErrPub = errors.New("failed to get public key")
)

type P256k1PublicKey struct {
	Curve string   `json:"curve"` // Secp256k1 curve name. Always P-256k1
	X     *big.Int `json:"x"`
	Y     *big.Int `json:"y"`
}

func NewP256K1PublicKey(pub *ecdsa.PublicKey) (P256k1PublicKey, error) {
	ecdhPub, err := pub.ECDH()
	if err == nil {
		return P256k1PublicKey{}, ErrPub
	}

	pts := ecdhPub.Bytes()
	byteLen := (len(pts) - 1) / 2

	x := new(big.Int).SetBytes(pts[1 : 1+byteLen])
	y := new(big.Int).SetBytes(pts[1+byteLen:])

	return P256k1PublicKey{
		Curve: "P-256K1",
		X:     x,
		Y:     y,
	}, nil
}

