package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/MyNextID/cvc-go/pkg"
)

func TestDeriveSecretKey(t *testing.T) {
	config := Config{}

	t.Run("ValidDerivation", func(t *testing.T) {
		// Generate a master key
		masterKey, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate master key: %v", err)
		}

		// Test data
		context := []byte("test-context-for-key-derivation")
		dst := []byte("CVC-TEST-DST-v1.0")

		// Derive a secret key
		derivedKey, err := config.DeriveSecretKey(masterKey, context, dst)
		if err != nil {
			t.Fatalf("DeriveSecretKey failed: %v", err)
		}

		// Verify the derived key is valid
		var privKey ecdsa.PrivateKey
		if err := derivedKey.Raw(&privKey); err != nil {
			t.Fatalf("Failed to extract derived private key: %v", err)
		}

		// Verify it's on the P-256 curve
		if privKey.Curve != elliptic.P256() {
			t.Errorf("Derived key is not on P-256 curve")
		}

		// Verify the public key point is valid (on the curve)
		if err = pkg.ValidatePublicKey(privKey.Curve, privKey.X, privKey.Y); err != nil {
			t.Errorf("Derived public key point is not on the curve")
		}

		// Verify private key is not zero
		if privKey.D.Sign() == 0 {
			t.Errorf("Derived private key is zero")
		}

		// Verify private key is in valid range [1, n-1]
		curveOrder := privKey.Curve.Params().N
		if privKey.D.Cmp(curveOrder) >= 0 {
			t.Errorf("Derived private key is not in valid range")
		}

		t.Logf("Successfully derived key. Private key D: %s", privKey.D.String())
		t.Logf("Public key X: %s, Y: %s", privKey.X.String(), privKey.Y.String())
	})

	t.Run("Deterministic", func(t *testing.T) {
		// Generate a master key
		masterKey, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate master key: %v", err)
		}

		context := []byte("deterministic-test")
		dst := []byte("CVC-DETERMINISTIC-DST-v1.0")

		// Derive the same key twice
		derivedKey1, err := config.DeriveSecretKey(masterKey, context, dst)
		if err != nil {
			t.Fatalf("First DeriveSecretKey failed: %v", err)
		}

		derivedKey2, err := config.DeriveSecretKey(masterKey, context, dst)
		if err != nil {
			t.Fatalf("Second DeriveSecretKey failed: %v", err)
		}

		// Extract private keys
		var privKey1, privKey2 ecdsa.PrivateKey
		if err := derivedKey1.Raw(&privKey1); err != nil {
			t.Fatalf("Failed to extract first derived private key: %v", err)
		}
		if err := derivedKey2.Raw(&privKey2); err != nil {
			t.Fatalf("Failed to extract second derived private key: %v", err)
		}

		// Verify they are identical
		if privKey1.D.Cmp(privKey2.D) != 0 {
			t.Errorf("Derived private keys are not identical")
		}
		if privKey1.X.Cmp(privKey2.X) != 0 || privKey1.Y.Cmp(privKey2.Y) != 0 {
			t.Errorf("Derived public keys are not identical")
		}

		t.Logf("Deterministic test passed - both derivations produced identical keys")
	})

	t.Run("DifferentContexts", func(t *testing.T) {
		// Generate a master key
		masterKey, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate master key: %v", err)
		}

		dst := []byte("CVC-CONTEXT-TEST-DST-v1.0")
		context1 := []byte("context-1")
		context2 := []byte("context-2")

		// Derive keys with different contexts
		derivedKey1, err := config.DeriveSecretKey(masterKey, context1, dst)
		if err != nil {
			t.Fatalf("First DeriveSecretKey failed: %v", err)
		}

		derivedKey2, err := config.DeriveSecretKey(masterKey, context2, dst)
		if err != nil {
			t.Fatalf("Second DeriveSecretKey failed: %v", err)
		}

		// Extract private keys
		var privKey1, privKey2 ecdsa.PrivateKey
		if err := derivedKey1.Raw(&privKey1); err != nil {
			t.Fatalf("Failed to extract first derived private key: %v", err)
		}
		if err := derivedKey2.Raw(&privKey2); err != nil {
			t.Fatalf("Failed to extract second derived private key: %v", err)
		}

		// Verify they are different
		if privKey1.D.Cmp(privKey2.D) == 0 {
			t.Errorf("Derived private keys should be different for different contexts")
		}
		if privKey1.X.Cmp(privKey2.X) == 0 && privKey1.Y.Cmp(privKey2.Y) == 0 {
			t.Errorf("Derived public keys should be different for different contexts")
		}

		t.Logf("Different contexts test passed - derivations produced different keys")
	})

	t.Run("DifferentDSTs", func(t *testing.T) {
		// Generate a master key
		masterKey, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate master key: %v", err)
		}

		context := []byte("same-context")
		dst1 := []byte("CVC-DST-1-v1.0")
		dst2 := []byte("CVC-DST-2-v1.0")

		// Derive keys with different DSTs
		derivedKey1, err := config.DeriveSecretKey(masterKey, context, dst1)
		if err != nil {
			t.Fatalf("First DeriveSecretKey failed: %v", err)
		}

		derivedKey2, err := config.DeriveSecretKey(masterKey, context, dst2)
		if err != nil {
			t.Fatalf("Second DeriveSecretKey failed: %v", err)
		}

		// Extract private keys
		var privKey1, privKey2 ecdsa.PrivateKey
		if err := derivedKey1.Raw(&privKey1); err != nil {
			t.Fatalf("Failed to extract first derived private key: %v", err)
		}
		if err := derivedKey2.Raw(&privKey2); err != nil {
			t.Fatalf("Failed to extract second derived private key: %v", err)
		}

		// Verify they are different
		if privKey1.D.Cmp(privKey2.D) == 0 {
			t.Errorf("Derived private keys should be different for different DSTs")
		}

		t.Logf("Different DSTs test passed - derivations produced different keys")
	})

	t.Run("ErrorCases", func(t *testing.T) {
		masterKey, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate master key: %v", err)
		}

		validContext := []byte("valid-context")
		validDST := []byte("CVC-ERROR-TEST-DST-v1.0")

		// Test nil master key
		_, err = config.DeriveSecretKey(nil, validContext, validDST)
		if err == nil {
			t.Errorf("Expected error for nil master key, but got none")
		}
		t.Logf("Correctly rejected nil master key: %v", err)

		// Test empty context
		_, err = config.DeriveSecretKey(masterKey, []byte{}, validDST)
		if err == nil {
			t.Errorf("Expected error for empty context, but got none")
		}
		t.Logf("Correctly rejected empty context: %v", err)

		// Test empty DST
		_, err = config.DeriveSecretKey(masterKey, validContext, []byte{})
		if err == nil {
			t.Errorf("Expected error for empty DST, but got none")
		}
		t.Logf("Correctly rejected empty DST: %v", err)

		// Test oversized context (>2048 bytes)
		oversizedContext := make([]byte, 2049)
		for i := range oversizedContext {
			oversizedContext[i] = byte(i % 256)
		}
		_, err = config.DeriveSecretKey(masterKey, oversizedContext, validDST)
		if err == nil {
			t.Errorf("Expected error for oversized context, but got none")
		}
		t.Logf("Correctly rejected oversized context: %v", err)

		// Test oversized DST (>256 bytes)
		oversizedDST := make([]byte, 257)
		for i := range oversizedDST {
			oversizedDST[i] = byte(i % 256)
		}
		_, err = config.DeriveSecretKey(masterKey, validContext, oversizedDST)
		if err == nil {
			t.Errorf("Expected error for oversized DST, but got none")
		}
		t.Logf("Correctly rejected oversized DST: %v", err)
	})

	t.Run("LargeInputs", func(t *testing.T) {
		// Test with maximum allowed sizes
		masterKey, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate master key: %v", err)
		}

		// Use large but valid inputs
		largeContext := make([]byte, 2048)
		for i := range largeContext {
			largeContext[i] = byte(i % 256)
		}

		largeDST := make([]byte, 256)
		for i := range largeDST {
			largeDST[i] = byte(i % 256)
		}

		derivedKey, err := config.DeriveSecretKey(masterKey, largeContext, largeDST)
		if err != nil {
			t.Fatalf("DeriveSecretKey failed with large inputs: %v", err)
		}

		// Verify the result is valid
		var privKey ecdsa.PrivateKey
		if err := derivedKey.Raw(&privKey); err != nil {
			t.Fatalf("Failed to extract derived private key: %v", err)
		}

		if !privKey.Curve.IsOnCurve(privKey.X, privKey.Y) {
			t.Errorf("Derived public key point is not on the curve")
		}

		t.Logf("Large inputs test passed")
	})

	t.Run("MultipleDerivations", func(t *testing.T) {
		// Test multiple derivations from the same master key
		masterKey, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate master key: %v", err)
		}

		dst := []byte("CVC-MULTIPLE-TEST-DST-v1.0")
		numDerivations := 10
		derivedKeys := make([]ecdsa.PrivateKey, numDerivations)

		// Derive multiple keys
		for i := 0; i < numDerivations; i++ {
			context := []byte(fmt.Sprintf("context-%d", i))

			derivedKey, err := config.DeriveSecretKey(masterKey, context, dst)
			if err != nil {
				t.Fatalf("DeriveSecretKey %d failed: %v", i, err)
			}

			if err := derivedKey.Raw(&derivedKeys[i]); err != nil {
				t.Fatalf("Failed to extract derived private key %d: %v", i, err)
			}

			// Verify each key is valid
			if !derivedKeys[i].Curve.IsOnCurve(derivedKeys[i].X, derivedKeys[i].Y) {
				t.Errorf("Derived key %d: public key point is not on the curve", i)
			}
		}

		// Verify all keys are different
		for i := 0; i < numDerivations; i++ {
			for j := i + 1; j < numDerivations; j++ {
				if derivedKeys[i].D.Cmp(derivedKeys[j].D) == 0 {
					t.Errorf("Derived keys %d and %d have identical private keys", i, j)
				}
			}
		}

		t.Logf("Multiple derivations test passed - generated %d unique keys", numDerivations)
	})
}
