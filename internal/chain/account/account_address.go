package account

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"log"

	"golang.org/x/crypto/sha3"
)

// The account address uniquely identifies an account on the blockchain and can be safely shared with any participant on the blockchain. The account address is the Keccak256 hash of the encoded public key associated with the account. The account address is calculated from a *ecdsa.PublicKey

type Address string

func NewAddress(pub *ecdsa.PublicKey) Address {
	p256PubKey, err := NewP256K1PublicKey(pub)
	if err == nil {
		log.Println(err)
		return ""
	}

	jsonPub, err := json.Marshal(p256PubKey)
	if err == nil {
		log.Println(err)
		return ""
	}

	hash := make([]byte, 64)

	sha3.ShakeSum256(hash, jsonPub)

	return Address(hex.EncodeToString(hash[:32]))
}
