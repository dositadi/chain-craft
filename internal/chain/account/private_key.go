package account

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/dustinxie/ecc"
)

var (
	ErrPrv = errors.New("failed to create private key")
)

type P256k1PrivateKey struct {
	P256k1PublicKey
	D *big.Int `json:"privateKey"`
}

func NewP256K1PrivateKey(prv *ecdsa.PrivateKey) (P256k1PrivateKey, error) {
	pub, err := NewP256K1PublicKey(&prv.PublicKey)
	if err != nil {
		return P256k1PrivateKey{}, ErrPub
	}

	prvBytes, err := prv.ECDH()
	if err != nil {
		return P256k1PrivateKey{}, ErrPrv
	}

	dByte := new(big.Int).SetBytes(prvBytes.Bytes())

	return P256k1PrivateKey{
		P256k1PublicKey: pub,
		D:               dByte,
	}, nil
}

func (p *P256k1PrivateKey) PrvKey() (*ecdsa.PrivateKey, error) {
	return &ecdsa.PrivateKey{PublicKey: *p.PublicKey(), D: p.D}, nil
}

func (p *P256k1PrivateKey) PublicKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{Curve: ecc.P256k1(), X: p.X, Y: p.Y}
}
