package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/deatil/go-jwt/jwt"
)

var (
	SigningES256K = NewSignES256K(crypto.SHA256, 32, "ES256K")

	SigningMethodES256K = jwt.NewJWT[*ecdsa.PrivateKey, *ecdsa.PublicKey](SigningES256K, jwt.NewJoseEncoder())
)

func init() {
	jwt.RegisterSigningMethod(SigningES256K.Alg(), func() any {
		return SigningES256K
	})
}

var (
	ErrSignES256KSignLengthInvalid = errors.New("go-jwt: sign length error")
	ErrSignES256KVerifyFail        = errors.New("go-jwt: SignES256K Verify fail")
)

// SignES256K implements the SM2 family of signing methods.
type SignES256K struct {
	Name    string
	Hash    crypto.Hash
	KeySize int
}

func NewSignES256K(hash crypto.Hash, keySize int, name string) *SignES256K {
	return &SignES256K{
		Name:    name,
		Hash:    hash,
		KeySize: keySize,
	}
}

// Signer algo name.
func (s *SignES256K) Alg() string {
	return s.Name
}

// Signer signed bytes length.
func (s *SignES256K) SignLength() int {
	return 2 * s.KeySize
}

// Sign implements token signing for the Signer.
func (s *SignES256K) Sign(msg []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	hasher := s.Hash.New()
	hasher.Write([]byte(msg))

	rr, ss, err := ecdsa.Sign(rand.Reader, key, hasher.Sum(nil))
	if err != nil {
		return nil, err
	}

	keyBytes := s.KeySize

	signed := make([]byte, 2*keyBytes)
	rr.FillBytes(signed[0:keyBytes])
	ss.FillBytes(signed[keyBytes:])

	return signed, nil
}

// Verify implements token verification for the Signer.
func (s *SignES256K) Verify(msg []byte, signature []byte, key *ecdsa.PublicKey) (bool, error) {
	signLength := s.SignLength()
	if len(signature) != signLength {
		return false, ErrSignES256KSignLengthInvalid
	}

	rr := big.NewInt(0).SetBytes(signature[:s.KeySize])
	ss := big.NewInt(0).SetBytes(signature[s.KeySize:])

	hasher := s.Hash.New()
	hasher.Write([]byte(msg))

	verifyStatus := ecdsa.Verify(key, hasher.Sum(nil), rr, ss)
	if !verifyStatus {
		return false, ErrSignES256KVerifyFail
	}

	return true, nil
}
