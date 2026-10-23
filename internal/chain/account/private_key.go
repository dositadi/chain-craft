package account

import (
	"crypto/ecdsa"
	"errors"
)

var (
	ErrPrv = errors.New("failed to create private key")
)

type P256k1PrivateKey struct {
	P256k1PublicKey
	PrivateKey []byte `json:"privateKey"`
}

func NewP256K1PrivateKey(prv *ecdsa.PrivateKey) (P256k1PrivateKey, error) {
	pub, err := NewP256K1PublicKey(&prv.PublicKey)
	if err != nil {
		return P256k1PrivateKey{}, ErrPub
	}

	prvKey, err := prv.ECDH()
	if err != nil {
		return P256k1PrivateKey{}, ErrPrv
	}

	return P256k1PrivateKey{
		P256k1PublicKey: pub,
		PrivateKey:      prvKey.Bytes(),
	}, nil
}
