package jwt_test

import (
	"crypto/ed25519"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
)

func TestStuff(t *testing.T) {
	var err error

	keyFile, _ := ioutil.ReadFile("test/test25519.pem")

	var key *ed25519.PrivateKey
	if key, err = jwt.ParseEdPrivateKeyFromPEM(keyFile); err != nil {
		t.Errorf("Unable to parse ECDSA private key: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(key)
	fmt.Printf("%s", tokenString)

	var claims jwt.StandardClaims

	_, err = jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (interface{}, error) {
		return key.Public(), nil
	})

	fmt.Printf("%+v", claims)
	fmt.Printf("%+v", err)
}
