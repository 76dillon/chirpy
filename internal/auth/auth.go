package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenType string

const (
	// TokenTypeAccess -
	TokenTypeAccess TokenType = "chirpy-access"
)

func HashPassword(password string) (string, error) {

	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return "", err
	}

	return hash, nil
}

func CheckPasswordHash(password, hash string) (bool, error) {
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return false, err
	}
	return match, nil
}

// MakeJWT
func MakeJWT(
	userID uuid.UUID,
	tokenSecret string,
	expiresIn time.Duration,
) (string, error) {
	signingKey := []byte(tokenSecret)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    string(TokenTypeAccess),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	})
	return token.SignedString(signingKey)
}

// ValidateJWT -
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claimsStruct,
		func(token *jwt.Token) (any, error) { return []byte(tokenSecret), nil },
	)
	if err != nil {
		return uuid.Nil, err
	}

	userIDString, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.Nil, err
	}

	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		return uuid.Nil, err
	}
	if issuer != string(TokenTypeAccess) {
		return uuid.Nil, errors.New("invalid issuer")
	}

	id, err := uuid.Parse(userIDString)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID: %w", err)
	}
	return id, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	for _, h := range headers.Values("Authorization") {
		trimmed := strings.TrimSpace(h)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "bearer ") {
			// strip from the original trimmed string to preserve token case
			token := strings.TrimSpace(trimmed[len("Bearer "):])
			if token != "" {
				return token, nil
			}
		}
	}
	return "", errors.New("no valid Bearer token found")
}

func MakeRefreshToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func GetAPIKey(headers http.Header) (string, error) {
	for _, h := range headers.Values("Authorization") {
		trimmed := strings.TrimSpace(h)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "apikey ") {
			// strip from the original trimmed string to preserve key case
			key := strings.TrimSpace(trimmed[len("ApiKey "):])
			if key != "" {
				return key, nil
			}
		}
	}
	return "", errors.New("no valid API key found")
}
