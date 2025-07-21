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
