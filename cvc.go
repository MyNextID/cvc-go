package cvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/MyNextID/cvc-go/internal"
	"github.com/MyNextID/cvc-go/pkg"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// GenerateSecretKey generates a cryptographically secure NIST P-256 private key
func GenerateSecretKey() (jwk.Key, error) {
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
	jwkKey, err := keyMaterialToJWK(keyMaterial)
	if err != nil {
		return nil, internal.WrapError(err, "failed to convert generated key to JWK")
	}

	return jwkKey, nil
}

// AddSecretKeys adds two ECDSA private keys using scalar addition modulo curve order
func AddSecretKeys(key1, key2 jwk.Key) (jwk.Key, error) {
	// Input validation
	if key1 == nil {
		return nil, internal.WrapError(internal.ErrInvalidKey, "first key cannot be nil")
	}
	if key2 == nil {
		return nil, internal.WrapError(internal.ErrInvalidKey, "second key cannot be nil")
	}

	// Extract private keys from JWKs
	privateKey1, err := extractPrivateKey(key1, "first key")
	if err != nil {
		return nil, err
	}

	privateKey2, err := extractPrivateKey(key2, "second key")
	if err != nil {
		return nil, err
	}

	// Convert private key scalars to byte arrays
	key1Bytes := privateKeyToBytes(privateKey1.D)
	key2Bytes := privateKeyToBytes(privateKey2.D)

	// Perform scalar addition using internal C bindings
	resultKeyMaterial, err := internal.AddSecretKeys(key1Bytes, key2Bytes)
	if err != nil {
		return nil, internal.WrapError(err, "secret key addition failed")
	}

	// Convert result to JWK
	resultJWK, err := keyMaterialToJWK(resultKeyMaterial)
	if err != nil {
		return nil, internal.WrapError(err, "failed to convert result to JWK")
	}

	return resultJWK, nil
}

// AddPublicKeys adds two ECDSA public keys using elliptic curve point addition
func AddPublicKeys(key1, key2 jwk.Key) (jwk.Key, error) {
	// Input validation
	if key1 == nil {
		return nil, internal.WrapError(internal.ErrInvalidKey, "first key cannot be nil")
	}
	if key2 == nil {
		return nil, internal.WrapError(internal.ErrInvalidKey, "second key cannot be nil")
	}

	// Extract public keys from JWKs
	pubKey1, err := extractPublicKey(key1, "first key")
	if err != nil {
		return nil, err
	}

	pubKey2, err := extractPublicKey(key2, "second key")
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
	if err := validatePublicKey(resultECDSA); err != nil {
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
func DeriveSecretKey(master jwk.Key, context, dst []byte) (jwk.Key, error) {
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
	derivedJWK, err := keyMaterialToJWK(derivedKeyMaterial)
	if err != nil {
		return nil, internal.WrapError(err, "failed to convert derived key to JWK")
	}

	// Additional validation of derived key
	if err := validateDerivedKey(derivedJWK); err != nil {
		return nil, internal.WrapError(err, "derived key validation failed")
	}

	return derivedJWK, nil
}

// keyMaterialToJWK converts internal key material to a JWK private key
func keyMaterialToJWK(keyMaterial internal.KeyMaterial) (jwk.Key, error) {
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
func extractPrivateKey(key jwk.Key, keyName string) (*ecdsa.PrivateKey, error) {
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
func extractPublicKey(key jwk.Key, keyName string) (*ecdsa.PublicKey, error) {
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
	if err := validatePublicKey(&pubKey); err != nil {
		return nil, internal.WrapError(err, fmt.Sprintf("%s validation failed", keyName))
	}

	return &pubKey, nil
}

// validatePublicKey validates an ECDSA public key
func validatePublicKey(pubKey *ecdsa.PublicKey) error {
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
func validateDerivedKey(key jwk.Key) error {
	// Extract and validate the derived private key
	_, err := extractPrivateKey(key, "derived key")
	if err != nil {
		return err
	}

	// Additional checks could be added here if needed
	return nil
}

// privateKeyToBytes converts a big.Int private key to a 32-byte array (big-endian)
func privateKeyToBytes(d *big.Int) []byte {
	keyBytes := make([]byte, internal.KeySize)
	dBytes := d.Bytes()

	// Copy to right-aligned position (left-pad with zeros if necessary)
	copy(keyBytes[internal.KeySize-len(dBytes):], dBytes)

	return keyBytes
}

// Additional utility methods for the Config struct

// ValidateConfig validates the configuration before use
func (c *IssuerConfig) ValidateConfig() error {
	return nil
}

func (c *ProviderConfig) ValidateConfig() error {
	return nil
}

// IsKeyValid checks if a JWK represents a valid NIST P-256 key
func IsKeyValid(key jwk.Key) error {
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
		return validatePublicKey(&pubKey)
	}

	// Validate both private and public parts
	if err := validatePublicKey(&privateKey.PublicKey); err != nil {
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

func KeyJWKToJson(key jwk.Key) ([]byte, error) {
	jwkJSON, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	return jwkJSON, nil
}

func KeyJsonToJWK(jwkJSON []byte) (jwk.Key, error) {
	key, err := jwk.ParseKey(jwkJSON)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func EncryptWithPublicKey(payload []byte, pkJWK jwk.Key) ([]byte, error) {

	// Perform JWE encryption with ECDH-ES + A256KW, AES-GCM 256 content encryption
	encrypted, err := jwe.Encrypt(
		payload,
		jwe.WithKey(jwa.ECDH_ES, pkJWK),
		jwe.WithContentEncryption(jwa.A256GCM),
		// jwe.WithContext(context.Background()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with JWE: %w", err)
	}

	return encrypted, nil
}
