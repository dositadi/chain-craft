package account

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"

	"github.com/dustinxie/ecc"
	"golang.org/x/crypto/argon2"
)

// The account contains the Secp256k1 private key and the account address derived from the corresponding Secp256k1 public key using the Keccak256 hash function. A new Secp256k1 key pair is generated when a new account is created.

type Account struct {
	privateKey *ecdsa.PrivateKey
	addr       Address
}

func NewAccount() (Account, error) {
	prv, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
	if err != nil {
		return Account{}, ErrPrv
	}

	addr := NewAddress(&prv.PublicKey)

	return Account{privateKey: prv, addr: addr}, nil
}

func (a Account) GetAccPrvKey() *ecdsa.PrivateKey {
	return a.privateKey
}
func (a Account) GetAccAddr() Address { return a.addr }

// Encode the private key
func (a Account) encodePrivateKey() ([]byte, error) {
	pk, err := NewP256K1PrivateKey(a.privateKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pk)
}

// decode the private key back
func (a Account) decodePrivateKey(jsonPrv []byte) (Account, error) {
	var pk P256k1PrivateKey

	if err := json.Unmarshal(jsonPrv, &pk); err != nil {
		return Account{}, err
	}

	prvKey, err := pk.PrvKey()
	if err != nil {
		return Account{}, err
	}
	addr := NewAddress(pk.PublicKey())

	return Account{privateKey: prvKey, addr: addr}, nil
}

/* AES-GCM encryption with Argon2 KDF
The encryption process
Argon2 Key Derivation Function (KDF) derives a cryptographically strong encryption key from the owner-provided password and a randomly generated salt
Create the AES block cipher that uses the derived cryptographically strong encryption key
Create the AES-GCM encryption mode from the AES block cipher
AES-GCM encrypts the encoded key pair with a randomly generated nonce
Pack the random salt, the random nonce, and the ciphertext all together into a slice of bytes to be written to a file. Both the random salt for the Argon2 KDF and the random nonce for the AES-GCM encryption are public, but must be unique
*/

var encKeyLen = uint32(32)

func EncryptWithPassword(msg, password []byte) ([]byte, error) {
	// Instantiate an empty salt byte
	salt := make([]byte, encKeyLen)

	// write some random data into the salt byte
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Derive the enncrytion key from the password
	key := argon2.IDKey(password, salt, 1, 256, 1, encKeyLen)

	// Use the derived key to create the encrypted aes block cipher
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create the gcm from the aes block cipher (gcm = galoisse counter mode)
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}

	// create a nounce byte with the gcm nounce size
	nounce := make([]byte, gcm.NonceSize())

	// Write some random data into the nounce byte
	if _, err := rand.Read(nounce); err != nil {
		return nil, err
	}

	// seal the random salt, nounce and the cipher text all together
	ciph := gcm.Seal(nounce, nounce, msg, nil)

	// append the ciph to the salt and assign it to ciph
	ciph = append(salt, ciph...)

	return ciph, nil
}
