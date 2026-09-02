package types

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenClaims represents the JWT claims
type TokenClaims struct {
	jwt.RegisteredClaims
	Service string `json:"service,omitempty"`
	MaxUses int    `json:"maxUses,omitempty"`
}

// GenerateToken creates a new JWT token
func GenerateToken(privateKey *rsa.PrivateKey, subject, service string, duration time.Duration, maxUses int) (string, error) {
	if privateKey == nil {
		return "", fmt.Errorf("private key is required")
	}

	now := time.Now()
	claims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    "etc-collector",
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
		},
		Service: service,
		MaxUses: maxUses,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// ValidateToken validates a JWT token and returns the claims
func ValidateToken(publicKey *rsa.PublicKey, tokenString string) (*TokenClaims, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is required")
	}

	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// IsExpired checks if the token is expired
func (c *TokenClaims) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(c.ExpiresAt.Time)
}
