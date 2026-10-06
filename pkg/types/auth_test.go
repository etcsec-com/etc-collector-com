package types

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

func TestGenerateToken(t *testing.T) {
	privateKey, _ := generateTestKeys(t)

	token, err := GenerateToken(privateKey, "test-user", "etc-collector", time.Hour, 0)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Token should be a valid JWT (three parts separated by dots)
	parts := 0
	for _, c := range token {
		if c == '.' {
			parts++
		}
	}
	assert.Equal(t, 2, parts, "JWT should have 3 parts (2 dots)")
}

func TestGenerateTokenWithNilKey(t *testing.T) {
	_, err := GenerateToken(nil, "test-user", "etc-collector", time.Hour, 0)
	assert.Error(t, err)
}

func TestValidateToken(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)

	// Generate a token
	token, err := GenerateToken(privateKey, "test-user", "etc-collector", time.Hour, 5)
	require.NoError(t, err)

	// Validate it
	claims, err := ValidateToken(publicKey, token)
	require.NoError(t, err)

	assert.Equal(t, "test-user", claims.Subject)
	assert.Equal(t, "etc-collector", claims.Service)
	assert.Equal(t, 5, claims.MaxUses)
	assert.Equal(t, "etc-collector", claims.Issuer)
	assert.NotEmpty(t, claims.ID)
}

func TestValidateTokenExpired(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)

	// Generate an already-expired token
	token, err := GenerateToken(privateKey, "test-user", "etc-collector", -time.Hour, 0)
	require.NoError(t, err)

	// Validation should fail
	_, err = ValidateToken(publicKey, token)
	assert.Error(t, err)
}

func TestValidateTokenWithNilKey(t *testing.T) {
	_, err := ValidateToken(nil, "some-token")
	assert.Error(t, err)
}

func TestValidateTokenInvalid(t *testing.T) {
	_, publicKey := generateTestKeys(t)

	_, err := ValidateToken(publicKey, "invalid-token")
	assert.Error(t, err)
}

func TestValidateTokenWrongKey(t *testing.T) {
	privateKey1, _ := generateTestKeys(t)
	_, publicKey2 := generateTestKeys(t)

	// Generate token with key 1
	token, err := GenerateToken(privateKey1, "test-user", "etc-collector", time.Hour, 0)
	require.NoError(t, err)

	// Try to validate with key 2
	_, err = ValidateToken(publicKey2, token)
	assert.Error(t, err)
}

func TestTokenClaimsIsExpired(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)

	// Valid token
	token, _ := GenerateToken(privateKey, "test", "svc", time.Hour, 0)
	claims, _ := ValidateToken(publicKey, token)
	assert.False(t, claims.IsExpired())

	// Note: Can't test truly expired claims easily since validation fails
}
