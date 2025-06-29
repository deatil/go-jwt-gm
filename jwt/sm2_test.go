package jwt

import (
	"crypto/rand"
	"testing"

	"github.com/deatil/go-cryptobin/gm/sm2"
	"github.com/deatil/go-jwt/jwt"
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

func Test_SigningMethodGmSM2_With_PEM_pkcs8_Key(t *testing.T) {
	var prikey = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg2Ji9WbkIxFNryxbJ
nxYYlBxEpAIZP9TTM912ucLhT6KhRANCAAT675f4f5kQyHG9bt2RM+eITRdHFEIb
ilK2LTA2MfCQ0yqsMGwddvZ+140DYnZTR+8w+J18hc2pzIPNYmRbJ8OZ
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE+u+X+H+ZEMhxvW7dkTPniE0XRxRC
G4pSti0wNjHwkNMqrDBsHXb2fteNA2J2U0fvMPidfIXNqcyDzWJkWyfDmQ==
-----END PUBLIC KEY-----
    `

	prikeyBytes, _ := jwt.ParsePEM([]byte(prikey))
	pubkeyBytes, _ := jwt.ParsePEM([]byte(pubkey))

	privateKey, err := ParseSM2PrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseSM2PublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodGmSM2.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
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

	if claims2["foo"].(string) != claims["foo"] {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), claims["foo"])
	}

}

func Test_SigningMethodGmSM2_With_PEM_pkcs1_Key(t *testing.T) {
	var prikey = `
-----BEGIN SM2 PRIVATE KEY-----
MHcCAQEEIFrbqCTUBARy9vLhjkQLrjAVLar7obsMM4nrA1E0GTTNoAoGCCqBHM9V
AYItoUQDQgAEepTjvwoxEFCW0gPxAXld7HKtsXbuDu1iWonCJUgSYHxt3uIRDhC/
cN3vGgJRCQFnEmjSRjmGkwlRUWxhxgZHfA==
-----END SM2 PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEepTjvwoxEFCW0gPxAXld7HKtsXbu
Du1iWonCJUgSYHxt3uIRDhC/cN3vGgJRCQFnEmjSRjmGkwlRUWxhxgZHfA==
-----END PUBLIC KEY-----
    `

	prikeyBytes, _ := jwt.ParsePEM([]byte(prikey))
	pubkeyBytes, _ := jwt.ParsePEM([]byte(pubkey))

	privateKey, err := ParseSM2PrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseSM2PublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodGmSM2.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
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

	if claims2["foo"].(string) != claims["foo"] {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), claims["foo"])
	}

}

func Test_SigningMethodGmSM2_Parse(t *testing.T) {
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

	parsed, err := jwt.Parse[*sm2.PrivateKey, *sm2.PublicKey](tokenString, publicKey)
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
