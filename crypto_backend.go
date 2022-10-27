package mockoidc

import "github.com/golang-jwt/jwt/v4"

// CryptoBackend backend interface implementing
// JWT crypto function
type CryptoBackend interface {
	JWKS() ([]byte, error)                      // marshal of JWKS
	SignJWT(claims jwt.Claims) (string, error)  // signs jwt claims
	VerifyJWT(token string) (*jwt.Token, error) // verify and parse JWT

}

// RSAKeyPairCryptoBackend RSA implementationg of a crypto backend
type RSAKeyPairCryptoBackend struct {
	Keypair *Keypair
}

func NewRSAKeyPairCryptoBackend(k *Keypair) *RSAKeyPairCryptoBackend {
	return &RSAKeyPairCryptoBackend{
		Keypair: k,
	}
}

func (r *RSAKeyPairCryptoBackend) JWKS() ([]byte, error) {
	return r.Keypair.JWKS()
}

func (r *RSAKeyPairCryptoBackend) SignJWT(claims jwt.Claims) (string, error) {
	return r.Keypair.SignJWT(claims)
}

func (r *RSAKeyPairCryptoBackend) VerifyJWT(token string) (*jwt.Token, error) {
	return r.Keypair.VerifyJWT(token)
}
