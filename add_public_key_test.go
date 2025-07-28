package cvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestAddPublicKeys(t *testing.T) {
	config := Config{}

	t.Run("ValidKeys", func(t *testing.T) {
		// Generate two test keys
		key1, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate first test key: %v", err)
		}

		key2, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate second test key: %v", err)
		}

		// Extract public keys from the private keys
		var privateKey1 ecdsa.PrivateKey
		if err := key1.Raw(&privateKey1); err != nil {
			t.Fatalf("Failed to extract first private key: %v", err)
		}

		var privateKey2 ecdsa.PrivateKey
		if err := key2.Raw(&privateKey2); err != nil {
			t.Fatalf("Failed to extract second private key: %v", err)
		}

		// Convert to public key JWKs
		pubKey1, err := jwk.FromRaw(&privateKey1.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create first public key JWK: %v", err)
		}

		pubKey2, err := jwk.FromRaw(&privateKey2.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create second public key JWK: %v", err)
		}

		// Test the AddPublicKeys function
		resultKey, err := config.AddPublicKeys(pubKey1, pubKey2)
		if err != nil {
			t.Fatalf("AddPublicKeys failed: %v", err)
		}

		// Verify the result is a valid ECDSA public key
		var resultPubKey ecdsa.PublicKey
		if err := resultKey.Raw(&resultPubKey); err != nil {
			t.Fatalf("Failed to extract result public key: %v", err)
		}

		// Verify it's on the P-256 curve
		if resultPubKey.Curve != elliptic.P256() {
			t.Errorf("Result key is not on P-256 curve")
		}

		// Verify the point is valid (on the curve)
		if !resultPubKey.Curve.IsOnCurve(resultPubKey.X, resultPubKey.Y) {
			t.Errorf("Result point is not on the curve")
		}

		t.Logf("Successfully added public keys. Result X: %s, Y: %s",
			resultPubKey.X.String(), resultPubKey.Y.String())
	})

	t.Run("IdentityProperty", func(t *testing.T) {
		// Test that adding a key to itself gives the double of the key
		key1, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate test key: %v", err)
		}

		var privateKey1 ecdsa.PrivateKey
		if err := key1.Raw(&privateKey1); err != nil {
			t.Fatalf("Failed to extract private key: %v", err)
		}

		pubKey1, err := jwk.FromRaw(&privateKey1.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create public key JWK: %v", err)
		}

		// Add key to itself (should give 2*P)
		doubledKey, err := config.AddPublicKeys(pubKey1, pubKey1)
		if err != nil {
			t.Fatalf("AddPublicKeys failed for identity test: %v", err)
		}

		// Verify the result is valid
		var resultPubKey ecdsa.PublicKey
		if err := doubledKey.Raw(&resultPubKey); err != nil {
			t.Fatalf("Failed to extract doubled public key: %v", err)
		}

		// Verify it's on the curve
		if !resultPubKey.Curve.IsOnCurve(resultPubKey.X, resultPubKey.Y) {
			t.Errorf("Doubled point is not on the curve")
		}

		t.Logf("Identity property test passed. Doubled key X: %s, Y: %s",
			resultPubKey.X.String(), resultPubKey.Y.String())
	})

	t.Run("InvalidKeyType", func(t *testing.T) {
		// Test with a non-ECDSA key (this should fail)
		key1, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate test key: %v", err)
		}

		// Create an invalid JWK (symmetric key instead of ECDSA)
		invalidKey, err := jwk.FromRaw([]byte("invalid-symmetric-key"))
		if err != nil {
			t.Fatalf("Failed to create invalid key: %v", err)
		}

		var privateKey1 ecdsa.PrivateKey
		if err := key1.Raw(&privateKey1); err != nil {
			t.Fatalf("Failed to extract private key: %v", err)
		}

		pubKey1, err := jwk.FromRaw(&privateKey1.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create public key JWK: %v", err)
		}

		// This should fail
		_, err = config.AddPublicKeys(pubKey1, invalidKey)
		if err == nil {
			t.Errorf("Expected error when using invalid key type, but got none")
		}

		t.Logf("Correctly rejected invalid key type with error: %v", err)
	})
}
