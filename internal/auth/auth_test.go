package auth

import (
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
