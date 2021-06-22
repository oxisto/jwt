package jwt

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	// Sadly this is missing from crypto/ecdsa compared to crypto/rsa
	ErrEdDSAVerification = errors.New("crypto/ed25519: verification error")
	ErrNotEdPrivateKey   = errors.New("not a ed25516 private key")
)

// Implements the ECDSA family of signing methods signing methods
// Expects *ecdsa.PrivateKey for signing and *ecdsa.PublicKey for verification
type SigningMethodED25519 struct {
	Name string
}

// Specific instances for EC256 and company
var (
	SigningMethodEdDSA *SigningMethodED25519
)

func init() {
	// EdDSA
	SigningMethodEdDSA = &SigningMethodED25519{"EdDSA"}
	RegisterSigningMethod(SigningMethodEdDSA.Alg(), func() SigningMethod {
		return SigningMethodEdDSA
	})
}

func (m *SigningMethodED25519) Alg() string {
	return m.Name
}

// Implements the Verify method from SigningMethod
// For this verify method, key must be an ecdsa.PublicKey struct
func (m *SigningMethodED25519) Verify(signingString, signature string, key interface{}) error {
	var err error

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	// Get the key
	var eddsaKey ed25519.PublicKey
	switch k := key.(type) {
	case *ed25519.PublicKey:
		eddsaKey = *k
	case ed25519.PublicKey:
		eddsaKey = k
	default:
		return ErrInvalidKeyType
	}

	if ed25519.Verify(eddsaKey, []byte(signingString), sig) {
		return nil
	}

	return ErrEdDSAVerification
}

// Implements the Sign method from SigningMethod
// For this signing method, key must be an ecdsa.PrivateKey struct
func (m *SigningMethodED25519) Sign(signingString string, key interface{}) (string, error) {
	// Get the key
	var eddsaKey *ed25519.PrivateKey
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		eddsaKey = k
	default:
		return "", ErrInvalidKeyType
	}

	// Sign the string and return out
	out := ed25519.Sign(*eddsaKey, []byte(signingString))

	return EncodeSegment(out), nil

}

// Parse PEM encoded Elliptic Curve Private Key Structure
func ParseEdPrivateKeyFromPEM(key []byte) (*ed25519.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return nil, err
	}

	var pkey ed25519.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(ed25519.PrivateKey); !ok {
		return nil, ErrNotEdPrivateKey
	}

	return &pkey, nil
}
