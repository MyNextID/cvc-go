package cvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/MyNextID/cvc-go/internal"
	"github.com/MyNextID/cvc-go/pkg"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Config holds the configuration for CVC operations
type Config struct {
	MasterKeyStore MasterKeyStore
	CredentialKey  []byte
}

// GenerateSecretKey generates a cryptographically secure NIST P-256 private key
func (c *Config) GenerateSecretKey() (jwk.Key, error) {
	// Generate cryptographically secure random seed
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, internal.WrapError(internal.ErrKeyGeneration, "failed to generate random seed")
	}

	// Generate key using internal C bindings
	keyMaterial, err := internal.GenerateSecretKey(seed)
	if err != nil {
		return nil, internal.WrapError(err, "key generation failed")
	}

	// Convert key material to JWK
	jwkKey, err := c.keyMaterialToJWK(keyMaterial)
	if err != nil {
		return nil, internal.WrapError(err, "failed to convert generated key to JWK")
	}

	return jwkKey, nil
}

// AddSecretKeys adds two ECDSA private keys using scalar addition modulo curve order
func (c *Config) AddSecretKeys(key1, key2 jwk.Key) (jwk.Key, error) {
	// Input validation
	if key1 == nil {
		return nil, internal.WrapError(internal.ErrInvalidKey, "first key cannot be nil")
	}
	if key2 == nil {
		return nil, internal.WrapError(internal.ErrInvalidKey, "second key cannot be nil")
	}

	// Extract private keys from JWKs
	privateKey1, err := c.extractPrivateKey(key1, "first key")
	if err != nil {
		return nil, err
	}

	privateKey2, err := c.extractPrivateKey(key2, "second key")
	if err != nil {
		return nil, err
	}

	// Convert private key scalars to byte arrays
	key1Bytes := c.privateKeyToBytes(privateKey1.D)
	key2Bytes := c.privateKeyToBytes(privateKey2.D)

	// Perform scalar addition using internal C bindings
	resultKeyMaterial, err := internal.AddSecretKeys(key1Bytes, key2Bytes)
	if err != nil {
		return nil, internal.WrapError(err, "secret key addition failed")
	}

	// Convert result to JWK
	resultJWK, err := c.keyMaterialToJWK(resultKeyMaterial)
	if err != nil {
		return nil, internal.WrapError(err, "failed to convert result to JWK")
	}

	return resultJWK, nil
}

// AddPublicKeys adds two ECDSA public keys using elliptic curve point addition
func (c *Config) AddPublicKeys(key1, key2 jwk.Key) (jwk.Key, error) {
	// Input validation
	if key1 == nil {
		return nil, internal.WrapError(internal.ErrInvalidKey, "first key cannot be nil")
	}
	if key2 == nil {
		return nil, internal.WrapError(internal.ErrInvalidKey, "second key cannot be nil")
	}

	// Extract public keys from JWKs
	pubKey1, err := c.extractPublicKey(key1, "first key")
	if err != nil {
		return nil, err
	}

	pubKey2, err := c.extractPublicKey(key2, "second key")
	if err != nil {
		return nil, err
	}

	// Convert to uncompressed point format
	pubKey1Bytes := pkg.PublicECDSAToBytes(pubKey1)
	pubKey2Bytes := pkg.PublicECDSAToBytes(pubKey2)

	// Perform point addition using internal C bindings
	resultBytes, err := internal.AddPublicKeys(pubKey1Bytes, pubKey2Bytes)
	if err != nil {
		return nil, internal.WrapError(err, "public key addition failed")
	}

	// Convert result back to ECDSA public key
	resultECDSA, err := pkg.PublicBytesToECDSA(resultBytes)
	if err != nil {
		return nil, internal.WrapError(internal.ErrResultConversion, "failed to convert result to ECDSA public key")
	}

	// Validate the resulting public key
	if err := c.validatePublicKey(resultECDSA); err != nil {
		return nil, internal.WrapError(err, "result public key validation failed")
	}

	// Convert to JWK
	resultJWK, err := jwk.FromRaw(resultECDSA)
	if err != nil {
		return nil, internal.WrapError(internal.ErrJWKCreation, "failed to create JWK from result public key")
	}

	return resultJWK, nil
}

// DeriveSecretKey derives a secret key from master key material using hash-to-field
func (c *Config) DeriveSecretKey(master jwk.Key, context, dst []byte) (jwk.Key, error) {
	// Input validation
	if master == nil {
		return nil, internal.WrapError(internal.ErrInvalidKey, "master key cannot be nil")
	}

	if err := internal.ValidateNonEmpty(context, "context"); err != nil {
		return nil, err
	}

	if err := internal.ValidateNonEmpty(dst, "domain separation tag"); err != nil {
		return nil, err
	}

	// Convert master JWK to JSON bytes for hashing
	masterBytes, err := pkg.JWKToJson(master)
	if err != nil {
		return nil, internal.WrapError(internal.ErrJWKExtraction, "failed to convert master key to JSON")
	}

	// Perform additional size validations
	if err := internal.ValidateInputSize(masterBytes, 2048, "master key JSON"); err != nil {
		return nil, err
	}

	if err := internal.ValidateInputSize(context, 2048, "context"); err != nil {
		return nil, err
	}

	if err := internal.ValidateInputSize(dst, 256, "domain separation tag"); err != nil {
		return nil, err
	}

	// Derive key using internal C bindings
	derivedKeyMaterial, err := internal.DeriveSecretKey(masterBytes, context, dst)
	if err != nil {
		return nil, internal.WrapError(err, "key derivation failed")
	}

	// Convert derived key material to JWK
	derivedJWK, err := c.keyMaterialToJWK(derivedKeyMaterial)
	if err != nil {
		return nil, internal.WrapError(err, "failed to convert derived key to JWK")
	}

	// Additional validation of derived key
	if err := c.validateDerivedKey(derivedJWK); err != nil {
		return nil, internal.WrapError(err, "derived key validation failed")
	}

	return derivedJWK, nil
}

// keyMaterialToJWK converts internal key material to a JWK private key
func (c *Config) keyMaterialToJWK(keyMaterial internal.KeyMaterial) (jwk.Key, error) {
	// Get key material as byte slices
	dBytes, xBytes, yBytes := keyMaterial.GetKeyMaterialBytes()

	// Convert to big.Int
	dBig := new(big.Int).SetBytes(dBytes)
	xBig := new(big.Int).SetBytes(xBytes)
	yBig := new(big.Int).SetBytes(yBytes)

	// Validate that we didn't get zero values
	if dBig.Sign() == 0 {
		return nil, internal.WrapError(internal.ErrZeroScalar, "private key scalar is zero")
	}

	if xBig.Sign() == 0 && yBig.Sign() == 0 {
		return nil, internal.WrapError(internal.ErrKeyAtInfinity, "public key coordinates are both zero")
	}

	// Create ECDSA key structures
	curve := elliptic.P256()
	ecdsaPub := &ecdsa.PublicKey{
		Curve: curve,
		X:     xBig,
		Y:     yBig,
	}

	// Validate that the public key point is on the curve
	if err := pkg.ValidatePublicKey(curve, xBig, yBig); err != nil {
		return nil, internal.WrapError(internal.ErrKeyNotOnCurve, "public key point validation failed")
	}

	ecdsaPrivate := &ecdsa.PrivateKey{
		PublicKey: *ecdsaPub,
		D:         dBig,
	}

	// Validate private key is in valid range [1, n-1]
	curveOrder := curve.Params().N
	if dBig.Cmp(curveOrder) >= 0 {
		return nil, internal.WrapError(internal.ErrKeyOutOfRange, "private key exceeds curve order")
	}

	// Convert to JWK
	jwkKey, err := jwk.FromRaw(ecdsaPrivate)
	if err != nil {
		return nil, internal.WrapError(internal.ErrJWKCreation, "failed to create JWK from ECDSA private key")
	}

	return jwkKey, nil
}

// extractPrivateKey extracts an ECDSA private key from a JWK
func (c *Config) extractPrivateKey(key jwk.Key, keyName string) (*ecdsa.PrivateKey, error) {
	var privateKey ecdsa.PrivateKey
	if err := key.Raw(&privateKey); err != nil {
		return nil, internal.WrapError(internal.ErrJWKExtraction, fmt.Sprintf("failed to extract %s as ECDSA private key", keyName))
	}

	// Validate curve
	if privateKey.Curve != elliptic.P256() {
		return nil, internal.WrapError(internal.ErrCurveUnsupported, fmt.Sprintf("%s is not on P-256 curve", keyName))
	}

	// Validate private key range
	if privateKey.D.Sign() <= 0 {
		return nil, internal.WrapError(internal.ErrZeroScalar, fmt.Sprintf("%s private key is not positive", keyName))
	}

	curveOrder := privateKey.Curve.Params().N
	if privateKey.D.Cmp(curveOrder) >= 0 {
		return nil, internal.WrapError(internal.ErrKeyOutOfRange, fmt.Sprintf("%s private key exceeds curve order", keyName))
	}

	return &privateKey, nil
}

// extractPublicKey extracts an ECDSA public key from a JWK
func (c *Config) extractPublicKey(key jwk.Key, keyName string) (*ecdsa.PublicKey, error) {
	// Try to extract as public key first
	var pubKey ecdsa.PublicKey
	if err := key.Raw(&pubKey); err != nil {
		// If that fails, try to extract as private key and get the public part
		var privateKey ecdsa.PrivateKey
		if err := key.Raw(&privateKey); err != nil {
			return nil, internal.WrapError(internal.ErrJWKExtraction, fmt.Sprintf("failed to extract %s as ECDSA key", keyName))
		}
		pubKey = privateKey.PublicKey
	}

	// Validate curve
	if pubKey.Curve != elliptic.P256() {
		return nil, internal.WrapError(internal.ErrCurveUnsupported, fmt.Sprintf("%s is not on P-256 curve", keyName))
	}

	// Validate public key
	if err := c.validatePublicKey(&pubKey); err != nil {
		return nil, internal.WrapError(err, fmt.Sprintf("%s validation failed", keyName))
	}

	return &pubKey, nil
}

// validatePublicKey validates an ECDSA public key
func (c *Config) validatePublicKey(pubKey *ecdsa.PublicKey) error {
	if pubKey.X == nil || pubKey.Y == nil {
		return internal.WrapError(internal.ErrInvalidKey, "public key coordinates are nil")
	}

	if pubKey.X.Sign() == 0 && pubKey.Y.Sign() == 0 {
		return internal.WrapError(internal.ErrKeyAtInfinity, "public key is at infinity")
	}

	// Use pkg validation function
	if err := pkg.ValidatePublicKey(pubKey.Curve, pubKey.X, pubKey.Y); err != nil {
		return internal.WrapError(internal.ErrKeyNotOnCurve, "public key point is not on curve")
	}

	return nil
}

// validateDerivedKey performs additional validation on a derived key
func (c *Config) validateDerivedKey(key jwk.Key) error {
	// Extract and validate the derived private key
	_, err := c.extractPrivateKey(key, "derived key")
	if err != nil {
		return err
	}

	// Additional checks could be added here if needed
	return nil
}

// privateKeyToBytes converts a big.Int private key to a 32-byte array (big-endian)
func (c *Config) privateKeyToBytes(d *big.Int) []byte {
	keyBytes := make([]byte, internal.KeySize)
	dBytes := d.Bytes()

	// Copy to right-aligned position (left-pad with zeros if necessary)
	copy(keyBytes[internal.KeySize-len(dBytes):], dBytes)

	return keyBytes
}

// Additional utility methods for the Config struct

// ValidateConfig validates the configuration before use
func (c *Config) ValidateConfig() error {
	if c.MasterKeyStore == nil {
		return internal.WrapError(internal.ErrMasterKeyNotSet, "master key store is not configured")
	}

	if len(c.CredentialKey) == 0 {
		return internal.WrapError(internal.ErrInvalidParameters, "credential key is not set")
	}

	// Test that we can retrieve the master key
	_, err := c.MasterKeyStore.GetMasterKey()
	if err != nil {
		return internal.WrapError(err, "failed to retrieve master key from store")
	}

	return nil
}

// GetMasterKey is a convenience method to get the master key
func (c *Config) GetMasterKey() (jwk.Key, error) {
	if c.MasterKeyStore == nil {
		return nil, internal.WrapError(internal.ErrMasterKeyNotSet, "master key store is not configured")
	}

	masterKey, err := c.MasterKeyStore.GetMasterKey()
	if err != nil {
		return nil, internal.WrapError(err, "failed to retrieve master key")
	}

	return masterKey, nil
}

// IsKeyValid checks if a JWK represents a valid NIST P-256 key
func (c *Config) IsKeyValid(key jwk.Key) error {
	if key == nil {
		return internal.WrapError(internal.ErrInvalidKey, "key is nil")
	}

	// Try to extract as private key first
	var privateKey ecdsa.PrivateKey
	if err := key.Raw(&privateKey); err != nil {
		// If that fails, try as public key
		var pubKey ecdsa.PublicKey
		if err := key.Raw(&pubKey); err != nil {
			return internal.WrapError(internal.ErrKeyTypeUnsupported, "key is not an ECDSA key")
		}
		return c.validatePublicKey(&pubKey)
	}

	// Validate both private and public parts
	if err := c.validatePublicKey(&privateKey.PublicKey); err != nil {
		return err
	}

	// Validate private key
	if privateKey.D.Sign() <= 0 {
		return internal.WrapError(internal.ErrZeroScalar, "private key is not positive")
	}

	curveOrder := privateKey.Curve.Params().N
	if privateKey.D.Cmp(curveOrder) >= 0 {
		return internal.WrapError(internal.ErrKeyOutOfRange, "private key exceeds curve order")
	}

	return nil
}
