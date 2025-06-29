## go-jwt-gm


### Desc

*  A JWT GM(China GuoMi) driver library for go.


### Download

~~~go
go get -u github.com/deatil/go-jwt-gm
~~~


### Get Starting

~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-jwt-gm/jwt"
)

func main() {
    claims := map[string]string{
        "aud": "example.com",
        "sub": "foo",
    }
    key := []byte("test-key")

    s := jwt.SigningMethodHSM3.New()
    tokenString, err := s.Sign(claims, key)
    if err != nil {
        fmt.Printf("Sign: %s \n", err.Error())
        return
    }

    fmt.Printf("Signed: %s \n", tokenString)

    p := jwt.SigningMethodHSM3.New()
    parsed, err := p.Parse(tokenString, key)
    if err != nil {
        fmt.Printf("Parse: %s \n", err.Error())
        return
    }

    claims2, err := parsed.GetClaims()
    if err != nil {
        fmt.Printf("GetClaims: %s \n", err.Error())
        return
    }

    aud := claims2["aud"].(string)
    fmt.Printf("Parseed aud: %s \n", aud)
}
~~~


### Signing Methods

The JWT GM driver library have signing methods:

 - `HSM3`: jwt.SigningMethodHSM3
 - `GmSM2`: jwt.SigningMethodGmSM2
 - `ES256K`: jwt.SigningMethodES256K


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
