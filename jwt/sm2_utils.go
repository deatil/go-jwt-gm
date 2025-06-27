package jwt

import (
	"github.com/deatil/go-cryptobin/gm/sm2"
)

// ParseECPrivateKeyFromDer parses a PEM encoded Elliptic Curve Private Key Structure
func ParseECPrivateKeyFromDer(der []byte) (*sm2.PrivateKey, error) {
	var err error
	var pkey *sm2.PrivateKey
	if pkey, err = sm2.ParseSM2PrivateKey(der); err != nil {
		if pkey, err = sm2.ParsePrivateKey(der); err != nil {
			return nil, err
		}
	}

	return pkey, nil
}

// ParseECPublicKeyFromDer parses a PEM encoded PKCS1 or PKCS8 public key
func ParseECPublicKeyFromDer(der []byte) (*sm2.PublicKey, error) {
	pkey, err := sm2.ParsePublicKey(der)
	if err != nil {
		return nil, err
	}

	return pkey, nil
}
