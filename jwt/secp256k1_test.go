package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/deatil/go-cryptobin/elliptic/secp256k1"
	"github.com/deatil/go-jwt/jwt"
)

func Test_SigningES256K(t *testing.T) {
	h := SigningES256K

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "ES256K" {
		t.Errorf("Alg got %s, want %s", alg, "ES256K")
	}
	if signLength != 64 {
		t.Errorf("SignLength got %d, want %d", signLength, 64)
	}

	var msg = "test-data"

	privateKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
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

func Test_SigningMethodES256K(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	s := SigningMethodES256K.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodES256K.New()
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

func Test_SigningMethodES256K_With_PEM_pkcs8_Key(t *testing.T) {
	var prikey = `
-----BEGIN PRIVATE KEY-----
MIGNAgEAMBAGByqGSM49AgEGBSuBBAAKBHYwdAIBAQQgXwlc0tnRDTIylE2tXJtF
D1N1yLh0R56GzIjwJiew0KKgBwYFK4EEAAqhRANCAATg1WObSzjzNfBHABuPCzrh
jiCs0KsuyNRswmmr+HxChkIJ+Z/HUSOR5liaSIDiJpsRj/fzh3+CECxRkDbjUNMB
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE4NVjm0s48zXwRwAbjws64Y4grNCrLsjU
bMJpq/h8QoZCCfmfx1EjkeZYmkiA4iabEY/384d/ghAsUZA241DTAQ==
-----END PUBLIC KEY-----
    `

	prikeyBytes, _ := jwt.ParsePEM([]byte(prikey))
	pubkeyBytes, _ := jwt.ParsePEM([]byte(pubkey))

	privateKey, err := ParseECPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseECPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodES256K.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodES256K.New()
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

func Test_SigningMethodES256K_With_PEM_pkcs1_Key(t *testing.T) {
	var prikey = `
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIEs6+PnCbiwPfXOGSBHMxZddhpDDqsSZdYA3lGeTpwsVoAcGBSuBBAAK
oUQDQgAEQ1wgUK0N9sXv9OcctpqfddGDJf65Pum6TVMvKDmmOd3mkMKl0aD3mDyK
G5oN4GNT842NVcAJMWorFXE1XdfrMQ==
-----END EC PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEQ1wgUK0N9sXv9OcctpqfddGDJf65Pum6
TVMvKDmmOd3mkMKl0aD3mDyKG5oN4GNT842NVcAJMWorFXE1XdfrMQ==
-----END PUBLIC KEY-----
    `

	prikeyBytes, _ := jwt.ParsePEM([]byte(prikey))
	pubkeyBytes, _ := jwt.ParsePEM([]byte(pubkey))

	privateKey, err := ParseECPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseECPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodES256K.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodES256K.New()
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

func Test_SigningMethodES256K_Parse(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	s := SigningMethodES256K.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.Parse[*ecdsa.PrivateKey, *ecdsa.PublicKey](tokenString, publicKey)
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

func Test_SigningMethodES256K_Check(t *testing.T) {
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJmb28iOiJiYXIifQ.Xe92dmU8MrI1d4edE2LEKqSmObZJpkIuz0fERihfn65ikTeeX5zjpyAdlHy9ZSBX8N8sqmJy5fxBTBzV26WvIQ"

	var prikey = `
-----BEGIN PRIVATE KEY-----
MIGNAgEAMBAGByqGSM49AgEGBSuBBAAKBHYwdAIBAQQgxOKd7ezy1P7xuzAMzj/P
yj7AhgZv09A+vDzHo27pAN2gBwYFK4EEAAqhRANCAATLzC6/r59eh0s8t+HGbXfb
LVHybh2SeDu0d7s36xQtXYS2HoDERdB934Tie5x5HbVQ0K9AqrGJjALNXAgpwd78
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEy8wuv6+fXodLPLfhxm132y1R8m4dkng7
tHe7N+sULV2Eth6AxEXQfd+E4nuceR21UNCvQKqxiYwCzVwIKcHe/A==
-----END PUBLIC KEY-----
    `

	prikeyBytes, _ := jwt.ParsePEM([]byte(prikey))
	pubkeyBytes, _ := jwt.ParsePEM([]byte(pubkey))

	privateKey, err := ParseECPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseECPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodES256K.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodES256K.New()
	parsed, err := p.Parse(tokenStr, publicKey)
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
