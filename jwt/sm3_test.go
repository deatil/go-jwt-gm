package jwt

import (
	"fmt"
	"testing"

	"github.com/deatil/go-jwt/jwt"
)

func Test_SigningHSM3(t *testing.T) {
	h := SigningHSM3

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "HSM3" {
		t.Errorf("Alg got %s, want %s", alg, "HSM3")
	}
	if signLength != 32 {
		t.Errorf("SignLength got %d, want %d", signLength, 32)
	}

	var msg = "test-data"
	var key = "test-key"
	var sign = "513eaa80de964ba335c4e64a9ac952546979e326a08f6a4b51f43daaf618c4f0"

	signed, err := h.Sign([]byte(msg), []byte(key))
	if err != nil {
		t.Fatal(err)
	}

	signature := fmt.Sprintf("%x", signed)
	if signature != sign {
		t.Errorf("Sign got %s, want %s", signature, sign)
	}

	veri, err := h.Verify([]byte(msg), signed, []byte(key))
	if err != nil {
		t.Fatal(err)
	}

	if !veri {
		t.Error("Verify fail")
	}

}

func Test_SigningMethodHSM3(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHSM3.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HSM3" {
		t.Errorf("Alg got %s, want %s", alg, "HSM3")
	}
	if signLength != 32 {
		t.Errorf("SignLength got %d, want %d", signLength, 32)
	}

	p := SigningMethodHSM3.New()
	parsed, err := p.Parse(tokenString, key)
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

func Test_SigningMethodHSM3_Parse(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHSM3.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HSM3" {
		t.Errorf("Alg got %s, want %s", alg, "HSM3")
	}
	if signLength != 32 {
		t.Errorf("SignLength got %d, want %d", signLength, 32)
	}

	parsed, err := jwt.Parse[[]byte, []byte](tokenString, key)
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
