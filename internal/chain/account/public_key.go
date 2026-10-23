package account

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
)

var (
	ErrPub = errors.New("failed to get public key")
)

type P256k1PublicKey struct {
	Curve     string `json:"curve"` // Secp256k1 curve name. Always P-256k1
	PublicKey []byte `json:"publicKey"`
}

func NewP256K1PublicKey(pub *ecdsa.PublicKey) (P256k1PublicKey, error) {
	ecdhPub, err := pub.ECDH()
	if err == nil {
		return P256k1PublicKey{}, ErrPub
	}

	fmt.Println(ecdhPub.Bytes())

	return P256k1PublicKey{
		Curve:     "P-256K1",
		PublicKey: ecdhPub.Bytes(),
	}, nil
}
