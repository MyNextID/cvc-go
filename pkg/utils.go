package pkg

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// GenerateUUID returns a new random UUID string.
func GenerateUUID() string {
	return uuid.NewString()
}

// Hash returns the SHA-256 hash of the input data.
func Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func JWKToJson(key jwk.Key) ([]byte, error) {
	jwkJSON, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	return jwkJSON, nil
}

func JsonToJWK(jwkJSON []byte) (jwk.Key, error) {
	key, err := jwk.ParseKey(jwkJSON)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GetProjectRoot attempts to find the project root by walking up from the current directory
func GetProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		// Check if go.mod exists here
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		// Go one level up
		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached root without finding go.mod
		}
		dir = parent
	}

	return "", os.ErrNotExist
}

func AddKeyToPayload(payload map[string]interface{}, pubKey jwk.Key) error {
	// Marshal JWK to JSON bytes
	jwkBytes, err := json.Marshal(pubKey)
	if err != nil {
		return err
	}

	// Unmarshal into map[string]interface{} for embedding
	var jwkMap map[string]interface{}
	err = json.Unmarshal(jwkBytes, &jwkMap)
	if err != nil {
		return err
	}

	// Construct VC payload map
	payload["cnf"] = map[string]interface{}{
		"jwk": jwkMap,
	}

	return nil
}

func ValidatePublicKey(curve elliptic.Curve, xBig, yBig *big.Int) error {
	// Convert curve to ecdh curve
	var ecdhCurve ecdh.Curve
	switch curve {
	case elliptic.P256():
		ecdhCurve = ecdh.P256()
	case elliptic.P384():
		ecdhCurve = ecdh.P384()
	case elliptic.P521():
		ecdhCurve = ecdh.P521()
	default:
		return fmt.Errorf("unsupported curve for ecdh validation")
	}

	// Marshal the point to uncompressed format
	pointBytes := elliptic.Marshal(curve, xBig, yBig)

	// Try to create an ecdh.PublicKey - this performs all necessary validation
	_, err := ecdhCurve.NewPublicKey(pointBytes)
	if err != nil {
		return fmt.Errorf("invalid public key point: %w", err)
	}

	return nil
}
