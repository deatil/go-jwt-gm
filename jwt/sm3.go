package jwt

import (
	"github.com/deatil/go-cryptobin/hash/sm3"
	"github.com/deatil/go-jwt/jwt"
)

var (
	SigningHSM3 = jwt.NewSignHmac(sm3.New, "HSM3")

	SigningMethodHSM3 = jwt.NewJWT[[]byte, []byte](SigningHSM3, jwt.JWTEncoder)
)

func init() {
	jwt.RegisterSigningMethod(SigningHSM3.Alg(), func() any {
		return SigningHSM3
	})
}
