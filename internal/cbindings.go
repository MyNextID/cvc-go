package internal

/*
#cgo CFLAGS: -I../include
#cgo darwin,arm64 LDFLAGS: -L../lib/darwin/arm64 -lcvc
#cgo linux,amd64 LDFLAGS: -L../lib/linux/x86_64 -lcvc
#cgo linux,arm64 LDFLAGS: -L../lib/linux/aarch64 -lcvc
#cgo windows,amd64 LDFLAGS: -L../lib/windows/x86_64 -lcvc

#include "big_256_56.h"
#include "nist256_key_material.h"
#include "ecp_operations.h"
#include "hash_to_field.h"
#include "add_secret_keys.h"
*/
import "C"
import (
	"unsafe"
)

const (
	// KeySize NIST P-256 key size in bytes
	KeySize = 32
	// UncompressedPublicKeySize (1 byte prefix + 32 bytes X + 32 bytes Y)
	UncompressedPublicKeySize = 65
)

// KeyMaterial represents extracted cryptographic key material
type KeyMaterial struct {
	PrivateKeyBytes [KeySize]byte
	PublicKeyXBytes [KeySize]byte
	PublicKeyYBytes [KeySize]byte
}

// GenerateSecretKey generates an NIST P-256 private key using cryptographically secure random data
func GenerateSecretKey(seed []byte) (KeyMaterial, error) {
	var keyMaterial KeyMaterial

	// Validate seed length (should be at least 32 bytes for good entropy)
	if len(seed) < KeySize {
		return keyMaterial, ErrInsufficientEntropy
	}

	// Generate NIST256 private key using C function
	var secretKeyBig C.BIG_256_56
	result := C.nist256_generate_secret_key(
		(*C.int64_t)(unsafe.Pointer(&secretKeyBig[0])),
		(*C.uchar)(unsafe.Pointer(&seed[0])),
		C.int(len(seed)),
	)

	if result != 0 {
		return keyMaterial, WrapError(
			MapSecretKeyError(CErrorCode(result)),
			"failed to generate secret key with C library",
		)
	}

	// Extract key material from the generated private key
	var cKeyMaterial C.nist256_key_material_t
	result = C.nist256_big_to_key_material(
		(*C.int64_t)(unsafe.Pointer(&secretKeyBig[0])),
		&cKeyMaterial,
	)

	if result != 0 {
		return keyMaterial, WrapError(
			ErrKeyMaterialExtraction,
			"failed to extract key material from generated private key",
		)
	}

	// Convert C arrays to Go arrays
	keyMaterial = convertCKeyMaterial(cKeyMaterial)

	return keyMaterial, nil
}

// AddSecretKeys adds two NIST P-256 private keys using scalar addition modulo curve order
func AddSecretKeys(key1Bytes, key2Bytes []byte) (KeyMaterial, error) {
	var keyMaterial KeyMaterial

	// Validate input key lengths
	if err := ValidateKeyLength(key1Bytes, KeySize, "first private key"); err != nil {
		return keyMaterial, err
	}

	if err := ValidateKeyLength(key2Bytes, KeySize, "second private key"); err != nil {
		return keyMaterial, err
	}

	// Call C function to add the secret keys
	var cKeyMaterial C.nist256_key_material_t
	result := C.cvc_add_nist256_secret_keys(
		(*C.uchar)(unsafe.Pointer(&key1Bytes[0])),
		C.int(len(key1Bytes)),
		(*C.uchar)(unsafe.Pointer(&key2Bytes[0])),
		C.int(len(key2Bytes)),
		&cKeyMaterial,
	)

	if result != 0 {
		return keyMaterial, MapSecretKeyError(CErrorCode(result))
	}

	// Convert C key material to Go
	keyMaterial = convertCKeyMaterial(cKeyMaterial)

	return keyMaterial, nil
}

// AddPublicKeys adds two NIST P-256 public keys using elliptic curve point addition
func AddPublicKeys(key1Bytes, key2Bytes []byte) ([]byte, error) {
	// Validate input key lengths (uncompressed format: 65 bytes)
	if err := ValidateKeyLength(key1Bytes, UncompressedPublicKeySize, "first public key"); err != nil {
		return nil, err
	}

	if err := ValidateKeyLength(key2Bytes, UncompressedPublicKeySize, "second public key"); err != nil {
		return nil, err
	}

	// Prepare result buffer for uncompressed public key
	resultBuffer := make([]byte, UncompressedPublicKeySize)
	var actualLen C.int

	// Call C function to add the public keys
	result := C.cvc_add_nist256_public_keys(
		(*C.uchar)(unsafe.Pointer(&key1Bytes[0])),
		C.int(len(key1Bytes)),
		(*C.uchar)(unsafe.Pointer(&key2Bytes[0])),
		C.int(len(key2Bytes)),
		(*C.uchar)(unsafe.Pointer(&resultBuffer[0])),
		C.int(len(resultBuffer)),
		&actualLen,
	)

	if result != 0 {
		return nil, MapECPError(CErrorCode(result))
	}

	// Validate that we got the expected result length
	if int(actualLen) != UncompressedPublicKeySize {
		return nil, WrapError(
			ErrResultConversion,
			"unexpected result length from public key addition",
		)
	}

	return resultBuffer[:actualLen], nil
}

// DeriveSecretKey derives a secret key from master key material using hash-to-field
func DeriveSecretKey(masterKeyBytes, context, dst []byte) (KeyMaterial, error) {
	var keyMaterial KeyMaterial

	// Validate input parameters
	if err := ValidateNonEmpty(masterKeyBytes, "master key"); err != nil {
		return keyMaterial, err
	}

	if err := ValidateNonEmpty(context, "context"); err != nil {
		return keyMaterial, err
	}

	if err := ValidateNonEmpty(dst, "domain separation tag"); err != nil {
		return keyMaterial, err
	}

	// Validate input sizes to prevent C buffer overflows
	if err := ValidateInputSize(masterKeyBytes, 2048, "master key"); err != nil {
		return keyMaterial, err
	}

	if err := ValidateInputSize(context, 2048, "context"); err != nil {
		return keyMaterial, err
	}

	if err := ValidateInputSize(dst, 256, "domain separation tag"); err != nil {
		return keyMaterial, err
	}

	// Check combined input size
	combinedSize := len(masterKeyBytes) + len(context)
	if combinedSize > 4096 {
		return keyMaterial, WrapError(
			ErrInputTooLarge,
			"combined master key and context exceed maximum size",
		)
	}

	// Prepare output structure for key material
	var cKeyMaterial C.nist256_key_material_t

	// Call C function to derive the secret key
	result := C.cvc_derive_secret_key_nist256(
		(*C.uchar)(unsafe.Pointer(&masterKeyBytes[0])),
		C.int(len(masterKeyBytes)),
		(*C.uchar)(unsafe.Pointer(&context[0])),
		C.int(len(context)),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
		C.int(len(dst)),
		&cKeyMaterial,
	)

	if result != 0 {
		return keyMaterial, MapDeriveKeyError(CErrorCode(result))
	}

	// Convert C key material to Go
	keyMaterial = convertCKeyMaterial(cKeyMaterial)

	// Additional validation of derived key material
	if err := validateKeyMaterial(keyMaterial); err != nil {
		return keyMaterial, WrapError(err, "derived key validation failed")
	}

	return keyMaterial, nil
}

// HashToField performs hash-to-field operation for the given input
func HashToField(hash, hashLen int, dst, message []byte, count int) error {
	// Validate input parameters
	if err := ValidateNonEmpty(dst, "domain separation tag"); err != nil {
		return err
	}

	if err := ValidateNonEmpty(message, "message"); err != nil {
		return err
	}

	if count <= 0 {
		return WrapError(ErrInvalidParameters, "count must be positive")
	}

	// Note: This is a simplified wrapper. The actual implementation would need
	// to handle field elements properly. For now, we'll just validate the call.
	result := C.cvc_hash_to_field_nist256(
		C.int(hash),
		C.int(hashLen),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
		C.int(len(dst)),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.int(len(message)),
		C.int(count),
		nil, // field_elements - would need proper implementation
	)

	if result != 0 {
		return MapHashToFieldError(CErrorCode(result))
	}

	return nil
}

// convertCKeyMaterial converts C key material structure to Go structure
func convertCKeyMaterial(cKeyMaterial C.nist256_key_material_t) KeyMaterial {
	var keyMaterial KeyMaterial

	// Convert C arrays to Go byte arrays
	// Note: C.GoBytes creates a copy, but we need fixed-size arrays
	for i := 0; i < KeySize; i++ {
		keyMaterial.PrivateKeyBytes[i] = byte(cKeyMaterial.private_key_bytes[i])
		keyMaterial.PublicKeyXBytes[i] = byte(cKeyMaterial.public_key_x_bytes[i])
		keyMaterial.PublicKeyYBytes[i] = byte(cKeyMaterial.public_key_y_bytes[i])
	}

	return keyMaterial
}

// validateKeyMaterial performs additional validation on extracted key material
func validateKeyMaterial(keyMaterial KeyMaterial) error {
	// Check that private key is not all zeros
	allZero := true
	for _, b := range keyMaterial.PrivateKeyBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ErrZeroScalar
	}

	// Check that public key coordinates are not both zero
	xAllZero := true
	yAllZero := true

	for _, b := range keyMaterial.PublicKeyXBytes {
		if b != 0 {
			xAllZero = false
			break
		}
	}

	for _, b := range keyMaterial.PublicKeyYBytes {
		if b != 0 {
			yAllZero = false
			break
		}
	}

	if xAllZero && yAllZero {
		return ErrKeyAtInfinity
	}

	return nil
}

// GetKeyMaterialBytes returns the key material as separate byte slices
func (km KeyMaterial) GetKeyMaterialBytes() (privateKey, publicKeyX, publicKeyY []byte) {
	privateKey = km.PrivateKeyBytes[:]
	publicKeyX = km.PublicKeyXBytes[:]
	publicKeyY = km.PublicKeyYBytes[:]
	return
}

// IsValid checks if the key material appears to be valid
func (km KeyMaterial) IsValid() bool {
	return validateKeyMaterial(km) == nil
}
