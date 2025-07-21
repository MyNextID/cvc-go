package pkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
)

// PublicECDSAToBytes elliptic.Marshal and elliptic.Unmarshal are deprecated in favor of the crypto/ecdh package, but that's specifically for ECDH operations. For ECDSA, these functions are still the standard way to handle point marshaling/unmarshaling, so we're good to use them.
func PublicECDSAToBytes(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

// PublicBytesToECDSA elliptic.Marshal and elliptic.Unmarshal are deprecated in favor of the crypto/ecdh package, but that's specifically for ECDH operations. For ECDSA, these functions are still the standard way to handle point marshaling/unmarshaling, so we're good to use them.
func PublicBytesToECDSA(data []byte) (*ecdsa.PublicKey, error) {
	// Ensure the key is for P-256 (adjust if you need other curves)
	curve := elliptic.P256()

	// Unmarshal into X and Y coordinates
	x, y := elliptic.Unmarshal(curve, data)
	if x == nil || y == nil {
		return nil, errors.New("failed to unmarshal elliptic public key")
	}

	// Construct ECDSA public key
	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return pubKey, nil
}
