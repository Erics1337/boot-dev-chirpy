package auth

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"
	expiresIn := time.Hour

	// Test successful creation and validation
	tokenString, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	validatedUserID, err := ValidateJWT(tokenString, secret)
	if err != nil {
		t.Fatalf("ValidateJWT failed for valid token: %v", err)
	}
	if validatedUserID != userID {
		t.Errorf("Validated user ID (%s) does not match original (%s)", validatedUserID, userID)
	}

	// Test validation with wrong secret
	_, err = ValidateJWT(tokenString, "wrong-secret")
	if err == nil {
		t.Errorf("ValidateJWT should have failed with wrong secret, but it succeeded")
	}

	// Test validation with expired token
	shortExpiresIn := -time.Hour // Expired an hour ago
	expiredTokenString, err := MakeJWT(userID, secret, shortExpiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed for expired token creation: %v", err)
	}

	_, err = ValidateJWT(expiredTokenString, secret)
	if err == nil {
		t.Errorf("ValidateJWT should have failed for expired token, but it succeeded")
	} else {
		// Check if the error indicates expiration (optional, depends on jwt library specifics)
		// fmt.Printf("Expired token validation error: %v\n", err) // Uncomment for debugging
	}
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name        string
		header      http.Header
		expected    string
		expectedErr error
	}{
		{
			name:        "Valid Bearer Token",
			header:      http.Header{"Authorization": {"Bearer mytoken123"}},
			expected:    "mytoken123",
			expectedErr: nil,
		},
		{
			name:        "Valid Bearer Token Lowercase",
			header:      http.Header{"Authorization": {"bearer mytoken456"}},
			expected:    "mytoken456",
			expectedErr: nil,
		},
		{
			name:        "No Authorization Header",
			header:      http.Header{},
			expected:    "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed - Missing Bearer",
			header:      http.Header{"Authorization": {"mytoken789"}},
			expected:    "",
			expectedErr: ErrMalformedAuthHeader,
		},
		{
			name:        "Malformed - Wrong Scheme",
			header:      http.Header{"Authorization": {"Basic mytokenabc"}},
			expected:    "",
			expectedErr: ErrMalformedAuthHeader,
		},
		{
			name:        "Malformed - Too Many Parts",
			header:      http.Header{"Authorization": {"Bearer mytoken extra"}},
			expected:    "",
			expectedErr: ErrMalformedAuthHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GetBearerToken(tt.header)
			if token != tt.expected {
				t.Errorf("Expected token '%s', got '%s'", tt.expected, token)
			}
			if err != tt.expectedErr {
				t.Errorf("Expected error '%v', got '%v'", tt.expectedErr, err)
			}
		})
	}
}

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		header      http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "Valid ApiKey",
			header:      http.Header{"Authorization": {"ApiKey mysecretkey123"}},
			expectedKey: "mysecretkey123",
			expectedErr: nil,
		},
		{
			name:        "Valid ApiKey Lowercase",
			header:      http.Header{"Authorization": {"apikey mysecretkey456"}},
			expectedKey: "mysecretkey456",
			expectedErr: nil,
		},
		{
			name:        "No Authorization Header",
			header:      http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Empty Authorization Header",
			header:      http.Header{"Authorization": {""}},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed - Missing ApiKey Prefix",
			header:      http.Header{"Authorization": {"mysecretkey789"}},
			expectedKey: "",
			expectedErr: ErrMalformedAuthHeader,
		},
		{
			name:        "Malformed - Wrong Scheme (Bearer)",
			header:      http.Header{"Authorization": {"Bearer mysecretkeyabc"}},
			expectedKey: "",
			expectedErr: ErrMalformedAuthHeader,
		},
		{
			name:        "Malformed - Too Many Parts",
			header:      http.Header{"Authorization": {"ApiKey mysecretkey extrapart"}},
			expectedKey: "",
			expectedErr: ErrMalformedAuthHeader,
		},
		{
			name:        "Malformed - Only ApiKey",
			header:      http.Header{"Authorization": {"ApiKey"}},
			expectedKey: "",
			expectedErr: ErrMalformedAuthHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.header)
			if key != tt.expectedKey {
				t.Errorf("Expected key '%s', got '%s'", tt.expectedKey, key)
			}
			// Use errors.Is for checking specific error types/values
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Expected error '%v', got '%v'", tt.expectedErr, err)
			}
		})
	}
}
