package internal

import (
	"errors"
	"fmt"
)

// Base error types for different categories of operations
var (
	// General errors
	ErrInvalidParameters = errors.New("invalid parameters provided")
	ErrInternalError     = errors.New("internal library error")
	ErrMemoryAllocation  = errors.New("memory allocation failed")

	// Key generation errors
	ErrKeyGeneration         = errors.New("failed to generate cryptographic key")
	ErrInsufficientEntropy   = errors.New("insufficient entropy for key generation")
	ErrKeyMaterialExtraction = errors.New("failed to extract key material")

	// Key validation errors
	ErrInvalidKey       = errors.New("invalid cryptographic key")
	ErrInvalidKeyLength = errors.New("invalid key length")
	ErrInvalidKeyFormat = errors.New("invalid key format")
	ErrKeyNotOnCurve    = errors.New("public key point is not on the curve")
	ErrKeyAtInfinity    = errors.New("key point is at infinity (invalid)")
	ErrZeroScalar       = errors.New("private key scalar is zero (invalid)")
	ErrKeyOutOfRange    = errors.New("private key is not in valid range")

	// Cryptographic operation errors
	ErrPointAddition      = errors.New("elliptic curve point addition failed")
	ErrScalarAddition     = errors.New("scalar addition failed")
	ErrResultConversion   = errors.New("failed to convert operation result")
	ErrInsufficientBuffer = errors.New("result buffer is too small")

	// Hash-to-field errors
	ErrHashToField       = errors.New("hash-to-field operation failed")
	ErrExpandMessage     = errors.New("message expansion failed")
	ErrExpansionTooLarge = errors.New("expansion length exceeds buffer limits")

	// Key derivation errors
	ErrKeyDerivation   = errors.New("key derivation failed")
	ErrInputTooLarge   = errors.New("input data too large")
	ErrContextTooLarge = errors.New("context data too large")
	ErrDSTTooLarge     = errors.New("domain separation tag too large")

	// JWK and encoding errors
	ErrJWKCreation        = errors.New("failed to create JWK")
	ErrJWKExtraction      = errors.New("failed to extract key from JWK")
	ErrKeyTypeUnsupported = errors.New("unsupported key type")
	ErrCurveUnsupported   = errors.New("unsupported elliptic curve")

	// Workflow errors (F0, F1 functions)
	ErrEmptyEmailMap       = errors.New("email map cannot be empty")
	ErrEmptyEmail          = errors.New("email cannot be empty")
	ErrEmptyUUID           = errors.New("uuid cannot be empty")
	ErrUserNotFound        = errors.New("user data not found")
	ErrMasterKeyNotSet     = errors.New("master key not available")
	ErrSaltGeneration      = errors.New("failed to generate salt")
	ErrPayloadModification = errors.New("failed to modify VC payload")
)

// CErrorCode represents C library error codes
type CErrorCode int

// MapSecretKeyError maps C secret key addition error codes to Go errors
func MapSecretKeyError(code CErrorCode) error {
	switch code {
	case 0: // CVC_ADD_SECRET_KEYS_SUCCESS
		return nil
	case -1: // CVC_ADD_SECRET_KEYS_ERROR_INVALID_PARAMS
		return fmt.Errorf("%w: invalid parameters for secret key addition", ErrInvalidParameters)
	case -2: // CVC_ADD_SECRET_KEYS_ERROR_INVALID_KEY1
		return fmt.Errorf("%w: first key is invalid (zero or >= curve order)", ErrInvalidKey)
	case -3: // CVC_ADD_SECRET_KEYS_ERROR_INVALID_KEY2
		return fmt.Errorf("%w: second key is invalid (zero or >= curve order)", ErrInvalidKey)
	case -4: // CVC_ADD_SECRET_KEYS_ERROR_RESULT_ZERO
		return fmt.Errorf("%w: result scalar is zero (invalid private key)", ErrZeroScalar)
	case -5: // CVC_ADD_SECRET_KEYS_ERROR_KEY_EXTRACTION_FAILED
		return fmt.Errorf("%w: failed to extract complete key material", ErrKeyMaterialExtraction)
	default:
		return fmt.Errorf("%w: secret key addition failed with error code %d", ErrInternalError, int(code))
	}
}

// MapECPError maps C ECP (elliptic curve point) operation error codes to Go errors
func MapECPError(code CErrorCode) error {
	switch code {
	case 0: // CVC_ECP_SUCCESS
		return nil
	case -1: // CVC_ECP_ERROR_INVALID_KEY1_LENGTH
		return fmt.Errorf("%w: first key has invalid length", ErrInvalidKeyLength)
	case -2: // CVC_ECP_ERROR_INVALID_KEY2_LENGTH
		return fmt.Errorf("%w: second key has invalid length", ErrInvalidKeyLength)
	case -3: // CVC_ECP_ERROR_INVALID_POINT_1
		return fmt.Errorf("%w: first key does not represent a valid ECP point", ErrInvalidKey)
	case -4: // CVC_ECP_ERROR_INVALID_POINT_2
		return fmt.Errorf("%w: second key does not represent a valid ECP point", ErrInvalidKey)
	case -5: // CVC_ECP_ERROR_POINT_1_AT_INFINITY
		return fmt.Errorf("%w: first point is at infinity (invalid)", ErrKeyAtInfinity)
	case -6: // CVC_ECP_ERROR_POINT_2_AT_INFINITY
		return fmt.Errorf("%w: second point is at infinity (invalid)", ErrKeyAtInfinity)
	case -7: // CVC_ECP_ERROR_RESULT_AT_INFINITY
		return fmt.Errorf("%w: result point is at infinity (invalid)", ErrKeyAtInfinity)
	case -8: // CVC_ECP_ERROR_RESULT_CONVERSION_FAILED
		return fmt.Errorf("%w: failed to convert result point to bytes", ErrResultConversion)
	case -9: // CVC_ECP_ERROR_INSUFFICIENT_BUFFER
		return fmt.Errorf("%w: result buffer is too small", ErrInsufficientBuffer)
	default:
		return fmt.Errorf("%w: ECP operation failed with error code %d", ErrPointAddition, int(code))
	}
}

// MapHashToFieldError maps C hash-to-field operation error codes to Go errors
func MapHashToFieldError(code CErrorCode) error {
	switch code {
	case 0: // CVC_HASH_TO_FIELD_SUCCESS
		return nil
	case -1: // CVC_HASH_TO_FIELD_ERROR_INVALID_PARAMS
		return fmt.Errorf("%w: invalid parameters for hash-to-field operation", ErrInvalidParameters)
	case -2: // CVC_HASH_TO_FIELD_ERROR_EXPAND_FAILED
		return fmt.Errorf("%w: XMD expansion failed", ErrExpandMessage)
	case -3: // CVC_HASH_TO_FIELD_ERROR_EXPANSION_TOO_LARGE
		return fmt.Errorf("%w: expansion length exceeds buffer limits", ErrExpansionTooLarge)
	default:
		return fmt.Errorf("%w: hash-to-field operation failed with error code %d", ErrHashToField, int(code))
	}
}

// MapDeriveKeyError maps C key derivation error codes to Go errors
func MapDeriveKeyError(code CErrorCode) error {
	switch code {
	case 0: // CVC_DERIVE_KEY_SUCCESS
		return nil
	case -1: // CVC_DERIVE_KEY_ERROR_INVALID_PARAMS
		return fmt.Errorf("%w: invalid parameters for key derivation", ErrInvalidParameters)
	case -2: // CVC_DERIVE_KEY_ERROR_INPUT_TOO_LARGE
		return fmt.Errorf("%w: combined input exceeds buffer limits", ErrInputTooLarge)
	case -3: // CVC_DERIVE_KEY_ERROR_HASH_TO_FIELD_FAILED
		return fmt.Errorf("%w: hash-to-field operation failed during key derivation", ErrHashToField)
	case -4: // CVC_DERIVE_KEY_ERROR_ZERO_SCALAR
		return fmt.Errorf("%w: derived key resulted in zero scalar (invalid)", ErrZeroScalar)
	case -5: // CVC_DERIVE_KEY_ERROR_KEY_EXTRACTION_FAILED
		return fmt.Errorf("%w: failed to extract derived key material", ErrKeyMaterialExtraction)
	default:
		return fmt.Errorf("%w: key derivation failed with error code %d", ErrKeyDerivation, int(code))
	}
}

// ValidateKeyLength validates that a key byte slice has the expected length
func ValidateKeyLength(keyBytes []byte, expectedLength int, keyName string) error {
	if len(keyBytes) != expectedLength {
		return fmt.Errorf("%w: %s has length %d, expected %d",
			ErrInvalidKeyLength, keyName, len(keyBytes), expectedLength)
	}
	return nil
}

// ValidateBufferSize validates that a buffer has sufficient capacity
func ValidateBufferSize(buffer []byte, requiredSize int, bufferName string) error {
	if len(buffer) < requiredSize {
		return fmt.Errorf("%w: %s has capacity %d, required %d",
			ErrInsufficientBuffer, bufferName, len(buffer), requiredSize)
	}
	return nil
}

// ValidateInputSize validates input size against maximum allowed
func ValidateInputSize(data []byte, maxSize int, dataName string) error {
	if len(data) > maxSize {
		return fmt.Errorf("%w: %s has size %d bytes, maximum allowed %d",
			ErrInputTooLarge, dataName, len(data), maxSize)
	}
	return nil
}

// ValidateNonEmpty validates that data is not empty
func ValidateNonEmpty(data []byte, dataName string) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: %s cannot be empty", ErrInvalidParameters, dataName)
	}
	return nil
}

// WrapError wraps an error with additional context
func WrapError(err error, context string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", context, err)
}

// IsKeyError checks if an error is related to key operations
func IsKeyError(err error) bool {
	return errors.Is(err, ErrInvalidKey) ||
		errors.Is(err, ErrInvalidKeyLength) ||
		errors.Is(err, ErrInvalidKeyFormat) ||
		errors.Is(err, ErrKeyNotOnCurve) ||
		errors.Is(err, ErrKeyAtInfinity) ||
		errors.Is(err, ErrZeroScalar) ||
		errors.Is(err, ErrKeyOutOfRange)
}

// IsCryptoError checks if an error is related to cryptographic operations
func IsCryptoError(err error) bool {
	return errors.Is(err, ErrPointAddition) ||
		errors.Is(err, ErrScalarAddition) ||
		errors.Is(err, ErrHashToField) ||
		errors.Is(err, ErrKeyDerivation)
}

// IsValidationError checks if an error is related to input validation
func IsValidationError(err error) bool {
	return errors.Is(err, ErrInvalidParameters) ||
		errors.Is(err, ErrInputTooLarge) ||
		errors.Is(err, ErrInvalidKeyLength) ||
		errors.Is(err, ErrInsufficientBuffer)
}
