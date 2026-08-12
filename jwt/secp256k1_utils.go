package jwt

import (
	"crypto/ecdsa"

	"github.com/deatil/go-jwt/jwt"
	"github.com/deatil/go-cryptobin/elliptic/secp256k1"
	pubkey_ecdsa "github.com/deatil/go-cryptobin/pubkey/ecdsa"
)

func init() {
	pubkey_ecdsa.AddNamedCurve(secp256k1.S256(), secp256k1.OIDNamedCurveSecp256k1)
}

// ParseECPrivateKeyFromPEM parses a PEM encoded PKCS1 or PKCS8 private key
func ParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
	der, err := jwt.ParsePEM(key)
	if err != nil {
		return nil, err
	}

	return ParseECPrivateKeyFromDer(der)
}

// ParseECPublicKeyFromPEM parses a PEM encoded PKCS8 public key
func ParseECPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error) {
	der, err := jwt.ParsePEM(key)
	if err != nil {
		return nil, err
	}

	return ParseECPublicKeyFromDer(der)
}

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

func ParseECPublicKeyFromDer(der []byte) (*ecdsa.PublicKey, error) {
	pkey, err := pubkey_ecdsa.ParsePublicKey(der)
	if err != nil {
		return nil, err
	}

	return pkey, nil
}
