package jwt

import (
	"crypto/rand"
	"errors"

	"github.com/deatil/go-cryptobin/gm/sm2"
	"github.com/deatil/go-jwt/jwt"
)

var (
	SigningGmSM2 = NewSignGmSM2(32, "GmSM2")

	SigningMethodGmSM2 = jwt.NewJWT[*sm2.PrivateKey, *sm2.PublicKey](SigningGmSM2, jwt.JWTEncoder)
)

func init() {
	jwt.RegisterSigningMethod(SigningGmSM2.Alg(), func() any {
		return SigningGmSM2
	})
}

var (
	ErrSignGmSM2SignLengthInvalid = errors.New("go-jwt: sign length error")
	ErrSignGmSM2VerifyFail        = errors.New("go-jwt: SignGmSM2 Verify fail")
)

// SignGmSM2 implements the SM2 family of signing methods.
type SignGmSM2 struct {
	Name    string
	KeySize int
}

func NewSignGmSM2(keySize int, name string) *SignGmSM2 {
	return &SignGmSM2{
		Name:    name,
		KeySize: keySize,
	}
}

// Signer algo name.
func (s *SignGmSM2) Alg() string {
	return s.Name
}

// Signer signed bytes length.
func (s *SignGmSM2) SignLength() int {
	return 2 * s.KeySize
}

// Sign implements token signing for the Signer.
func (s *SignGmSM2) Sign(msg []byte, key *sm2.PrivateKey) ([]byte, error) {
	signed, err := sm2.SignBytes(rand.Reader, key, msg, nil)
	if err != nil {
		return nil, err
	}

	return signed, nil
}

// Verify implements token verification for the Signer.
func (s *SignGmSM2) Verify(msg []byte, signature []byte, key *sm2.PublicKey) (bool, error) {
	signLength := s.SignLength()
	if len(signature) != signLength {
		return false, ErrSignGmSM2SignLengthInvalid
	}

	verifyStatus := sm2.VerifyBytes(key, msg, signature, nil)
	if !verifyStatus {
		return false, ErrSignGmSM2VerifyFail
	}

	return true, nil
}
