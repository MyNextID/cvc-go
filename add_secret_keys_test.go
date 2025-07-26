package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestAddSecretKeys(t *testing.T) {
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

		// Test the AddSecretKeys function
		resultKey, err := config.AddSecretKeys(key1, key2)
		if err != nil {
			t.Fatalf("AddSecretKeys failed: %v", err)
		}

		// Verify the result is a valid ECDSA private key
		var resultPrivKey ecdsa.PrivateKey
		if err := resultKey.Raw(&resultPrivKey); err != nil {
			t.Fatalf("Failed to extract result private key: %v", err)
		}

		// Verify it's on the P-256 curve
		if resultPrivKey.Curve != elliptic.P256() {
			t.Errorf("Result key is not on P-256 curve")
		}

		// Verify the private key is in valid range [1, n-1]
		curveOrder := resultPrivKey.Curve.Params().N
		if resultPrivKey.D.Sign() <= 0 {
			t.Errorf("Result private key is not positive")
		}
		if resultPrivKey.D.Cmp(curveOrder) >= 0 {
			t.Errorf("Result private key is not less than curve order")
		}

		// Verify the public key point is valid (on the curve)
		if !resultPrivKey.Curve.IsOnCurve(resultPrivKey.X, resultPrivKey.Y) {
			t.Errorf("Result public key point is not on the curve")
		}

		t.Logf("Successfully added secret keys. Result private key D: %s", resultPrivKey.D.String())
		t.Logf("Result public key X: %s, Y: %s", resultPrivKey.X.String(), resultPrivKey.Y.String())
	})

	t.Run("IdentityProperty", func(t *testing.T) {
		// Test that adding a key to itself gives the double of the key
		key1, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate test key: %v", err)
		}

		// Extract the original private key
		var origPrivKey ecdsa.PrivateKey
		if err := key1.Raw(&origPrivKey); err != nil {
			t.Fatalf("Failed to extract original private key: %v", err)
		}

		// Add key to itself (should give 2*d mod n)
		doubledKey, err := config.AddSecretKeys(key1, key1)
		if err != nil {
			t.Fatalf("AddSecretKeys failed for identity test: %v", err)
		}

		// Extract the doubled private key
		var doubledPrivKey ecdsa.PrivateKey
		if err := doubledKey.Raw(&doubledPrivKey); err != nil {
			t.Fatalf("Failed to extract doubled private key: %v", err)
		}

		// Verify arithmetic: (d + d) mod n = 2*d mod n
		curveOrder := origPrivKey.Curve.Params().N
		expected := new(big.Int).Add(origPrivKey.D, origPrivKey.D)
		expected.Mod(expected, curveOrder)

		if doubledPrivKey.D.Cmp(expected) != 0 {
			t.Errorf("Key doubling arithmetic is incorrect. Expected: %s, Got: %s",
				expected.String(), doubledPrivKey.D.String())
		}

		// Verify the result is valid
		if !doubledPrivKey.Curve.IsOnCurve(doubledPrivKey.X, doubledPrivKey.Y) {
			t.Errorf("Doubled key public point is not on the curve")
		}

		t.Logf("Identity property test passed. Original D: %s, Doubled D: %s",
			origPrivKey.D.String(), doubledPrivKey.D.String())
	})

	t.Run("CommutativeProperty", func(t *testing.T) {
		// Test that key addition is commutative: key1 + key2 = key2 + key1
		key1, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate first test key: %v", err)
		}

		key2, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate second test key: %v", err)
		}

		// Add in both orders
		result1, err := config.AddSecretKeys(key1, key2)
		if err != nil {
			t.Fatalf("First AddSecretKeys failed: %v", err)
		}

		result2, err := config.AddSecretKeys(key2, key1)
		if err != nil {
			t.Fatalf("Second AddSecretKeys failed: %v", err)
		}

		// Extract the results
		var privKey1, privKey2 ecdsa.PrivateKey
		if err := result1.Raw(&privKey1); err != nil {
			t.Fatalf("Failed to extract first result private key: %v", err)
		}
		if err := result2.Raw(&privKey2); err != nil {
			t.Fatalf("Failed to extract second result private key: %v", err)
		}

		// Verify they are identical
		if privKey1.D.Cmp(privKey2.D) != 0 {
			t.Errorf("Addition is not commutative for private keys. key1+key2: %s, key2+key1: %s",
				privKey1.D.String(), privKey2.D.String())
		}

		if privKey1.X.Cmp(privKey2.X) != 0 || privKey1.Y.Cmp(privKey2.Y) != 0 {
			t.Errorf("Addition is not commutative for public keys")
		}

		t.Logf("Commutative property test passed - both orders produced identical results")
	})

	t.Run("ErrorCases", func(t *testing.T) {
		validKey, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate valid test key: %v", err)
		}

		// Test nil first key
		_, err = config.AddSecretKeys(nil, validKey)
		if err == nil {
			t.Errorf("Expected error for nil first key, but got none")
		}
		t.Logf("Correctly rejected nil first key: %v", err)

		// Test nil second key
		_, err = config.AddSecretKeys(validKey, nil)
		if err == nil {
			t.Errorf("Expected error for nil second key, but got none")
		}
		t.Logf("Correctly rejected nil second key: %v", err)

		// Test both nil keys
		_, err = config.AddSecretKeys(nil, nil)
		if err == nil {
			t.Errorf("Expected error for both nil keys, but got none")
		}
		t.Logf("Correctly rejected both nil keys: %v", err)

		// Test with invalid key type (symmetric key instead of ECDSA)
		invalidKey, err := jwk.FromRaw([]byte("invalid-symmetric-key-data"))
		if err != nil {
			t.Fatalf("Failed to create invalid key: %v", err)
		}

		_, err = config.AddSecretKeys(validKey, invalidKey)
		if err == nil {
			t.Errorf("Expected error when using invalid key type, but got none")
		}
		t.Logf("Correctly rejected invalid key type: %v", err)
	})

	t.Run("ArithmeticVerification", func(t *testing.T) {
		// Test that the arithmetic is correct by manually verifying
		key1, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate first test key: %v", err)
		}

		key2, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate second test key: %v", err)
		}

		// Extract private keys
		var privKey1, privKey2 ecdsa.PrivateKey
		if err := key1.Raw(&privKey1); err != nil {
			t.Fatalf("Failed to extract first private key: %v", err)
		}
		if err := key2.Raw(&privKey2); err != nil {
			t.Fatalf("Failed to extract second private key: %v", err)
		}

		// Perform addition using the library
		resultKey, err := config.AddSecretKeys(key1, key2)
		if err != nil {
			t.Fatalf("AddSecretKeys failed: %v", err)
		}

		var resultPrivKey ecdsa.PrivateKey
		if err := resultKey.Raw(&resultPrivKey); err != nil {
			t.Fatalf("Failed to extract result private key: %v", err)
		}

		// Manually compute expected result: (d1 + d2) mod n
		curveOrder := privKey1.Curve.Params().N
		expected := new(big.Int).Add(privKey1.D, privKey2.D)
		expected.Mod(expected, curveOrder)

		// Verify the private key arithmetic
		if resultPrivKey.D.Cmp(expected) != 0 {
			t.Errorf("Private key arithmetic is incorrect. Expected: %s, Got: %s",
				expected.String(), resultPrivKey.D.String())
		}

		// Verify that the public key is consistent (resultPublic = expected * G)
		expectedX, expectedY := privKey1.Curve.ScalarBaseMult(expected.Bytes())
		if resultPrivKey.X.Cmp(expectedX) != 0 || resultPrivKey.Y.Cmp(expectedY) != 0 {
			t.Errorf("Public key is not consistent with private key arithmetic")
		}

		t.Logf("Arithmetic verification passed. Expected: %s, Got: %s",
			expected.String(), resultPrivKey.D.String())
	})

	t.Run("MultipleAdditions", func(t *testing.T) {
		// Test multiple sequential additions
		keys := make([]jwk.Key, 5)
		for i := 0; i < 5; i++ {
			key, err := config.GenerateSecretKey()
			if err != nil {
				t.Fatalf("Failed to generate key %d: %v", i, err)
			}
			keys[i] = key
		}

		// Add keys sequentially: ((key0 + key1) + key2) + key3) + key4
		result := keys[0]
		for i := 1; i < len(keys); i++ {
			newResult, err := config.AddSecretKeys(result, keys[i])
			if err != nil {
				t.Fatalf("Failed to add key %d: %v", i, err)
			}
			result = newResult
		}

		// Verify the final result is valid
		var finalPrivKey ecdsa.PrivateKey
		if err := result.Raw(&finalPrivKey); err != nil {
			t.Fatalf("Failed to extract final private key: %v", err)
		}

		// Verify it's on the curve and in valid range
		if !finalPrivKey.Curve.IsOnCurve(finalPrivKey.X, finalPrivKey.Y) {
			t.Errorf("Final public key point is not on the curve")
		}

		curveOrder := finalPrivKey.Curve.Params().N
		if finalPrivKey.D.Sign() <= 0 || finalPrivKey.D.Cmp(curveOrder) >= 0 {
			t.Errorf("Final private key is not in valid range")
		}

		t.Logf("Multiple additions test passed. Final private key: %s", finalPrivKey.D.String())
	})

	t.Run("LargeNumberHandling", func(t *testing.T) {
		// Test with keys that have large private key values (near curve order)
		// This tests edge cases in modular arithmetic

		key1, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate first key: %v", err)
		}

		key2, err := config.GenerateSecretKey()
		if err != nil {
			t.Fatalf("Failed to generate second key: %v", err)
		}

		// Add them multiple times to increase the scalar values
		for i := 0; i < 10; i++ {
			newKey, err := config.AddSecretKeys(key1, key2)
			if err != nil {
				t.Fatalf("Failed to add keys in iteration %d: %v", i, err)
			}
			key1 = newKey
		}

		// Verify the final result is still valid
		var finalPrivKey ecdsa.PrivateKey
		if err := key1.Raw(&finalPrivKey); err != nil {
			t.Fatalf("Failed to extract final private key: %v", err)
		}

		// Verify it's still in valid range after many additions
		curveOrder := finalPrivKey.Curve.Params().N
		if finalPrivKey.D.Sign() <= 0 || finalPrivKey.D.Cmp(curveOrder) >= 0 {
			t.Errorf("Private key after many additions is not in valid range")
		}

		if !finalPrivKey.Curve.IsOnCurve(finalPrivKey.X, finalPrivKey.Y) {
			t.Errorf("Public key after many additions is not on the curve")
		}

		t.Logf("Large number handling test passed after 10 iterations")
	})
}
