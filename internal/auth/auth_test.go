package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCheckPasswordHash(t *testing.T) {
	// First, we need to create some hashed passwords for testing
	password1 := "correctPassword123!"
	password2 := "anotherPassword456!"
	hash1, _ := HashPassword(password1)
	hash2, _ := HashPassword(password2)

	tests := []struct {
		name          string
		password      string
		hash          string
		wantErr       bool
		matchPassword bool
	}{
		{
			name:          "Correct password",
			password:      password1,
			hash:          hash1,
			wantErr:       false,
			matchPassword: true,
		},
		{
			name:          "Incorrect password",
			password:      "wrongPassword",
			hash:          hash1,
			wantErr:       false,
			matchPassword: false,
		},
		{
			name:          "Password doesn't match different hash",
			password:      password1,
			hash:          hash2,
			wantErr:       false,
			matchPassword: false,
		},
		{
			name:          "Empty password",
			password:      "",
			hash:          hash1,
			wantErr:       false,
			matchPassword: false,
		},
		{
			name:          "Invalid hash",
			password:      password1,
			hash:          "invalidhash",
			wantErr:       true,
			matchPassword: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := CheckPasswordHash(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && match != tt.matchPassword {
				t.Errorf("CheckPasswordHash() expects %v, got %v", tt.matchPassword, match)
			}
		})
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	validToken, _ := MakeJWT(userID, "secret", time.Hour)

	tests := []struct {
		name        string
		tokenString string
		tokenSecret string
		wantUserID  uuid.UUID
		wantErr     bool
	}{
		{
			name:        "Valid token",
			tokenString: validToken,
			tokenSecret: "secret",
			wantUserID:  userID,
			wantErr:     false,
		},
		{
			name:        "Invalid token",
			tokenString: "invalid.token.string",
			tokenSecret: "secret",
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			name:        "Wrong secret",
			tokenString: validToken,
			tokenSecret: "wrong_secret",
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserID, err := ValidateJWT(tt.tokenString, tt.tokenSecret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotUserID != tt.wantUserID {
				t.Errorf("ValidateJWT() gotUserID = %v, want %v", gotUserID, tt.wantUserID)
			}
		})
	}
}

func TestValidateGetBearerToken(t *testing.T) {

	tests := []struct {
		name     string
		input    http.Header
		expected string
		wantErr  bool
	}{
		{
			name:     "simple valid",
			input:    http.Header{"Authorization": []string{"Bearer abc123"}},
			expected: "abc123",
			wantErr:  false,
		},
		{
			name:    "no header",
			input:   http.Header{},
			wantErr: true,
		},
		{
			name:     "multiple headers: case 1",
			input:    http.Header{"Authorization": []string{"Basic x", "Bearer y"}, "X-Other": []string{"val"}},
			expected: "y",
			wantErr:  false,
		},
		{
			name:     "multiple headers: case 2",
			input:    http.Header{"Authorization": []string{"Bearer y", "Bearer z"}},
			expected: "y",
			wantErr:  false,
		},
		{
			name:    "multiple headers: case 3",
			input:   http.Header{"Authorization": []string{"Basic x", "Token t"}},
			wantErr: true,
		},
		{
			name:     "Weird but valid token content",
			input:    http.Header{"Authorization": []string{"Bearer a.b.c"}},
			expected: "a.b.c",
			wantErr:  false,
		},
		{
			name:     "Extra spaces",
			input:    http.Header{"Authorization": []string{"Bearer abc123 "}},
			expected: "abc123",
			wantErr:  false,
		},
		{
			name:     "Case-insensitive scheme",
			input:    http.Header{"Authorization": []string{"bearer abc123"}},
			expected: "abc123",
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GetBearerToken(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if token != tt.expected {
				t.Errorf("GetBearerToken() token = %v, want %v", token, tt.expected)
			}
		})
	}

}
