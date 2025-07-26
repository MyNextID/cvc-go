package main

/*
#cgo CFLAGS: -I./include
#cgo darwin,arm64 LDFLAGS: -L./lib/darwin/arm64 -lcvc
#cgo linux,amd64 LDFLAGS: -L./lib/linux/x86_64 -lcvc
#cgo linux,arm64 LDFLAGS: -L./lib/linux/aarch64 -lcvc
#cgo windows,amd64 LDFLAGS: -L./lib/windows/x86_64 -lcvc

#include "big_256_56.h"
#include "nist256_key_material.h"
#include "ecp_operations.h"
#include "hash_to_field.h"
#include "add_secret_keys.h"
*/
import "C"
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/MyNextID/cvc-go/pkg"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Config struct {
	MasterKeyStore MasterKeyStore
	CredentialKey  []byte
}

// GenerateSecretKey generates a secret key using the CVC library
func (*Config) GenerateSecretKey() (jwk.Key, error) {
	// Generate 32 bytes of cryptographically secure random data
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	// Generate NIST256 private key using C function
	var secretKeyBig C.BIG_256_56
	result := C.nist256_generate_secret_key(
		(*C.int64_t)(unsafe.Pointer(&secretKeyBig[0])), // Get pointer to first element
		(*C.uchar)(unsafe.Pointer(&seed[0])),
		C.int(len(seed)),
	)
	if result != 0 {
		return nil, fmt.Errorf("failed to generate secret key: %v", result)
	}

	// Extract key material and convert to JWK
	var keyMaterial C.nist256_key_material_t
	result = C.nist256_big_to_key_material(
		(*C.int64_t)(unsafe.Pointer(&secretKeyBig[0])), // Get pointer to first element
		&keyMaterial,
	)
	if result != 0 {
		return nil, fmt.Errorf("failed to extract key material: %v", result)
	}

	// Convert C arrays to Go byte slices
	// Note: MODBYTES_256_56 should be 32 for NIST P-256
	const keySize = 32
	xBytes := C.GoBytes(unsafe.Pointer(&keyMaterial.public_key_x_bytes[0]), keySize)
	yBytes := C.GoBytes(unsafe.Pointer(&keyMaterial.public_key_y_bytes[0]), keySize)
	dBytes := C.GoBytes(unsafe.Pointer(&keyMaterial.private_key_bytes[0]), keySize)

	// Convert to Go's standard crypto types and create JWK
	xBig := new(big.Int).SetBytes(xBytes)
	yBig := new(big.Int).SetBytes(yBytes)
	dBig := new(big.Int).SetBytes(dBytes)

	curve := elliptic.P256()
	ecdsaPub := &ecdsa.PublicKey{
		Curve: curve,
		X:     xBig,
		Y:     yBig,
	}
	ecdsaPrivate := &ecdsa.PrivateKey{
		PublicKey: *ecdsaPub,
		D:         dBig,
	}

	return jwk.FromRaw(ecdsaPrivate)
}

// AddPublicKeys adds two ECDSA public keys using elliptic curve point addition
func (*Config) AddPublicKeys(key1 jwk.Key, key2 jwk.Key) (jwk.Key, error) {
	// Extract raw ECDSA public keys
	var raw1 ecdsa.PublicKey
	if err := key1.Raw(&raw1); err != nil {
		return nil, fmt.Errorf("failed to extract first key: %w", err)
	}

	var raw2 ecdsa.PublicKey
	if err := key2.Raw(&raw2); err != nil {
		return nil, fmt.Errorf("failed to extract second key: %w", err)
	}

	// Validate that both keys are on P-256 curve
	if raw1.Curve != elliptic.P256() {
		return nil, fmt.Errorf("first key is not on P-256 curve")
	}
	if raw2.Curve != elliptic.P256() {
		return nil, fmt.Errorf("second key is not on P-256 curve")
	}

	// Convert to uncompressed point format
	pkBytes1 := pkg.PublicECDSAToBytes(&raw1)
	pkBytes2 := pkg.PublicECDSAToBytes(&raw2)

	// Prepare result buffer (65 bytes for uncompressed P-256 point)
	resultBuffer := make([]byte, 65)
	var actualLen C.int

	// Call C function to add the public keys
	result := C.cvc_add_nist256_public_keys(
		(*C.uchar)(unsafe.Pointer(&pkBytes1[0])),
		C.int(len(pkBytes1)),
		(*C.uchar)(unsafe.Pointer(&pkBytes2[0])),
		C.int(len(pkBytes2)),
		(*C.uchar)(unsafe.Pointer(&resultBuffer[0])),
		C.int(len(resultBuffer)),
		&actualLen,
	)

	if result != C.CVC_ECP_SUCCESS {
		return nil, fmt.Errorf("failed to add public keys: error code %d", int(result))
	}

	// Convert result back to ECDSA public key
	newECDSA, err := pkg.PublicBytesToECDSA(resultBuffer[:actualLen])
	if err != nil {
		return nil, fmt.Errorf("failed to convert result to ECDSA: %w", err)
	}

	// Convert to JWK
	return jwk.FromRaw(newECDSA)
}

// DeriveSecretKey derives a secret key from a master key using hash-to-field
func (*Config) DeriveSecretKey(master jwk.Key, context []byte, dst []byte) (jwk.Key, error) {
	// Input validation
	if master == nil {
		return nil, fmt.Errorf("master key cannot be nil")
	}
	if len(context) == 0 {
		return nil, fmt.Errorf("context cannot be empty")
	}
	if len(dst) == 0 {
		return nil, fmt.Errorf("domain separation tag cannot be empty")
	}

	// Convert master JWK to JSON bytes
	masterBytes, err := pkg.JWKToJson(master)
	if err != nil {
		return nil, fmt.Errorf("failed to convert master key to JSON: %w", err)
	}

	// Validate input sizes to prevent C buffer overflows
	if len(masterBytes) > 2048 {
		return nil, fmt.Errorf("master key too large: %d bytes (max 2048)", len(masterBytes))
	}
	if len(context) > 2048 {
		return nil, fmt.Errorf("context too large: %d bytes (max 2048)", len(context))
	}
	if len(dst) > 256 {
		return nil, fmt.Errorf("domain separation tag too large: %d bytes (max 256)", len(dst))
	}
	if len(masterBytes)+len(context) > 4096 {
		return nil, fmt.Errorf("combined master key and context too large: %d bytes (max 4096)", len(masterBytes)+len(context))
	}

	// Prepare output structure for key material
	var keyMaterial C.nist256_key_material_t

	// Call C function to derive the secret key
	result := C.cvc_derive_secret_key_nist256(
		(*C.uchar)(unsafe.Pointer(&masterBytes[0])),
		C.int(len(masterBytes)),
		(*C.uchar)(unsafe.Pointer(&context[0])),
		C.int(len(context)),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
		C.int(len(dst)),
		&keyMaterial,
	)

	// Handle C function errors
	if result != C.CVC_DERIVE_KEY_SUCCESS {
		switch result {
		case C.CVC_DERIVE_KEY_ERROR_INVALID_PARAMS:
			return nil, fmt.Errorf("invalid parameters provided to key derivation")
		case C.CVC_DERIVE_KEY_ERROR_INPUT_TOO_LARGE:
			return nil, fmt.Errorf("input data too large for key derivation")
		case C.CVC_DERIVE_KEY_ERROR_HASH_TO_FIELD_FAILED:
			return nil, fmt.Errorf("hash-to-field operation failed")
		case C.CVC_DERIVE_KEY_ERROR_ZERO_SCALAR:
			return nil, fmt.Errorf("derived key resulted in zero scalar (invalid)")
		case C.CVC_DERIVE_KEY_ERROR_KEY_EXTRACTION_FAILED:
			return nil, fmt.Errorf("failed to extract key material")
		default:
			return nil, fmt.Errorf("key derivation failed with error code: %d", int(result))
		}
	}

	// Convert C key material to Go types
	const keySize = 32 // MODBYTES_256_56 should be 32 for NIST P-256

	xBytes := C.GoBytes(unsafe.Pointer(&keyMaterial.public_key_x_bytes[0]), keySize)
	yBytes := C.GoBytes(unsafe.Pointer(&keyMaterial.public_key_y_bytes[0]), keySize)
	dBytes := C.GoBytes(unsafe.Pointer(&keyMaterial.private_key_bytes[0]), keySize)

	// Validate that we got valid key material
	if len(xBytes) != keySize || len(yBytes) != keySize || len(dBytes) != keySize {
		return nil, fmt.Errorf("invalid key material size returned from C function")
	}

	// Convert to Go's standard crypto types
	xBig := new(big.Int).SetBytes(xBytes)
	yBig := new(big.Int).SetBytes(yBytes)
	dBig := new(big.Int).SetBytes(dBytes)

	// Validate that we didn't get zero values
	if xBig.Sign() == 0 && yBig.Sign() == 0 {
		return nil, fmt.Errorf("derived public key coordinates are zero (invalid)")
	}
	if dBig.Sign() == 0 {
		return nil, fmt.Errorf("derived private key is zero (invalid)")
	}

	// Create ECDSA key structures
	curve := elliptic.P256()

	ecdsaPub := &ecdsa.PublicKey{
		Curve: curve,
		X:     xBig,
		Y:     yBig,
	}

	// Validate that the public key point is on the curve
	if err = pkg.ValidatePublicKey(curve, xBig, yBig); err != nil {
		return nil, fmt.Errorf("derived public key validation failed: %w", err)
	}

	ecdsaPrivate := &ecdsa.PrivateKey{
		PublicKey: *ecdsaPub,
		D:         dBig,
	}

	// Validate private key is in valid range [1, n-1] where n is curve order
	curveOrder := curve.Params().N
	if dBig.Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("derived private key is not in valid range")
	}

	// Convert to JWK
	derivedKey, err := jwk.FromRaw(ecdsaPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from derived key: %w", err)
	}

	return derivedKey, nil
}

// AddSecretKeys adds two ECDSA private keys using scalar addition modulo curve order
func (*Config) AddSecretKeys(key1 jwk.Key, key2 jwk.Key) (jwk.Key, error) {
	// Input validation
	if key1 == nil {
		return nil, fmt.Errorf("first key cannot be nil")
	}
	if key2 == nil {
		return nil, fmt.Errorf("second key cannot be nil")
	}

	// Extract raw ECDSA private keys
	var privKey1, privKey2 ecdsa.PrivateKey
	if err := key1.Raw(&privKey1); err != nil {
		return nil, fmt.Errorf("failed to extract first private key: %w", err)
	}
	if err := key2.Raw(&privKey2); err != nil {
		return nil, fmt.Errorf("failed to extract second private key: %w", err)
	}

	// Validate that both keys are on P-256 curve
	if privKey1.Curve != elliptic.P256() {
		return nil, fmt.Errorf("first key is not on P-256 curve")
	}
	if privKey2.Curve != elliptic.P256() {
		return nil, fmt.Errorf("second key is not on P-256 curve")
	}

	// Convert private key scalars to 32-byte arrays (big-endian)
	const keySize = 32 // MODBYTES_256_56 for NIST P-256

	// Ensure we have exactly 32 bytes for each key (left-pad with zeros if necessary)
	key1Bytes := make([]byte, keySize)
	key2Bytes := make([]byte, keySize)

	d1Bytes := privKey1.D.Bytes()
	d2Bytes := privKey2.D.Bytes()

	// Copy to right-aligned position (left-pad with zeros)
	copy(key1Bytes[keySize-len(d1Bytes):], d1Bytes)
	copy(key2Bytes[keySize-len(d2Bytes):], d2Bytes)

	// Prepare output structure for key material
	var keyMaterial C.nist256_key_material_t

	// Call C function to add the secret keys
	result := C.cvc_add_nist256_secret_keys(
		(*C.uchar)(unsafe.Pointer(&key1Bytes[0])),
		C.int(len(key1Bytes)),
		(*C.uchar)(unsafe.Pointer(&key2Bytes[0])),
		C.int(len(key2Bytes)),
		&keyMaterial,
	)

	// Handle C function errors
	if result != C.CVC_ADD_SECRET_KEYS_SUCCESS {
		switch result {
		case C.CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS:
			return nil, fmt.Errorf("invalid parameters provided to secret key addition")
		case C.CVC_ADD_SECRET_KEYS_ERROR_INVALID_KEY1:
			return nil, fmt.Errorf("first key is invalid (zero or >= curve order)")
		case C.CVC_ADD_SECRET_KEYS_ERROR_INVALID_KEY2:
			return nil, fmt.Errorf("second key is invalid (zero or >= curve order)")
		case C.CVC_ADD_SECRET_KEYS_ERROR_RESULT_ZERO:
			return nil, fmt.Errorf("result scalar is zero (invalid private key)")
		case C.CVC_ADD_SECRET_KEYS_ERROR_KEY_EXTRACTION_FAILED:
			return nil, fmt.Errorf("failed to extract complete key material")
		default:
			return nil, fmt.Errorf("secret key addition failed with error code: %d", int(result))
		}
	}

	// Convert C key material to Go types
	xBytes := C.GoBytes(unsafe.Pointer(&keyMaterial.public_key_x_bytes[0]), keySize)
	yBytes := C.GoBytes(unsafe.Pointer(&keyMaterial.public_key_y_bytes[0]), keySize)
	dBytes := C.GoBytes(unsafe.Pointer(&keyMaterial.private_key_bytes[0]), keySize)

	// Validate that we got valid key material
	if len(xBytes) != keySize || len(yBytes) != keySize || len(dBytes) != keySize {
		return nil, fmt.Errorf("invalid key material size returned from C function")
	}

	// Convert to Go's standard crypto types
	xBig := new(big.Int).SetBytes(xBytes)
	yBig := new(big.Int).SetBytes(yBytes)
	dBig := new(big.Int).SetBytes(dBytes)

	// Validate that we didn't get zero values
	if xBig.Sign() == 0 && yBig.Sign() == 0 {
		return nil, fmt.Errorf("result public key coordinates are zero (invalid)")
	}
	if dBig.Sign() == 0 {
		return nil, fmt.Errorf("result private key is zero (invalid)")
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
		return nil, fmt.Errorf("result public key validation failed: %w", err)
	}

	ecdsaPrivate := &ecdsa.PrivateKey{
		PublicKey: *ecdsaPub,
		D:         dBig,
	}

	// Validate private key is in valid range [1, n-1] where n is curve order
	curveOrder := curve.Params().N
	if dBig.Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("result private key is not in valid range")
	}

	// Convert to JWK
	resultKey, err := jwk.FromRaw(ecdsaPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from result key: %w", err)
	}

	return resultKey, nil
}
