package jwt

import (
	"crypto/rand"
	"testing"

	"github.com/deatil/go-cryptobin/gm/sm2"
)

func Test_SigningGmSM2(t *testing.T) {
	h := SigningGmSM2

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "GmSM2" {
		t.Errorf("Alg got %s, want %s", alg, "GmSM2")
	}
	if signLength != 64 {
		t.Errorf("SignLength got %d, want %d", signLength, 64)
	}

	var msg = "test-data"

	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	signed, err := h.Sign([]byte(msg), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	veri, err := h.Verify([]byte(msg), signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !veri {
		t.Error("Verify fail")
	}

}

func Test_SigningMethodGmSM2(t *testing.T) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	s := SigningMethodGmSM2.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodGmSM2.New()
	parsed, err := p.Parse(tokenString, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}
