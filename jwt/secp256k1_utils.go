package jwt

import (
	"crypto/ecdsa"

	"github.com/deatil/go-cryptobin/elliptic/secp256k1"
	pubkey_ecdsa "github.com/deatil/go-cryptobin/pubkey/ecdsa"
)

func init() {
	pubkey_ecdsa.AddNamedCurve(secp256k1.S256(), secp256k1.OIDNamedCurveSecp256k1)
}

// ParseECPrivateKeyFromDer parses a PEM encoded PKCS1 or PKCS8 private key
func ParseECPrivateKeyFromDer(der []byte) (*ecdsa.PrivateKey, error) {
	var err error
	var pkey *ecdsa.PrivateKey
	if pkey, err = pubkey_ecdsa.ParseECPrivateKey(der); err != nil {
		if pkey, err = pubkey_ecdsa.ParsePrivateKey(der); err != nil {
			return nil, err
		}
	}

	return pkey, nil
}

// ParseECPublicKeyFromDer parses a PEM encoded PKCS8 public key
func ParseECPublicKeyFromDer(der []byte) (*ecdsa.PublicKey, error) {
	pkey, err := pubkey_ecdsa.ParsePublicKey(der)
	if err != nil {
		return nil, err
	}

	return pkey, nil
}
