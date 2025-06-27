package jwt

import (
	"github.com/deatil/go-cryptobin/gm/sm2"
)

// ParseSM2PrivateKeyFromDer parses a PEM encoded PKCS1 or PKCS8 private key
func ParseSM2PrivateKeyFromDer(der []byte) (*sm2.PrivateKey, error) {
	var err error
	var pkey *sm2.PrivateKey
	if pkey, err = sm2.ParseSM2PrivateKey(der); err != nil {
		if pkey, err = sm2.ParsePrivateKey(der); err != nil {
			return nil, err
		}
	}

	return pkey, nil
}

// ParseSM2PublicKeyFromDer parses a PEM encoded PKCS8 public key
func ParseSM2PublicKeyFromDer(der []byte) (*sm2.PublicKey, error) {
	pkey, err := sm2.ParsePublicKey(der)
	if err != nil {
		return nil, err
	}

	return pkey, nil
}
