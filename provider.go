package cvc

import (
	"encoding/json"
	"fmt"

	"github.com/MyNextID/cvc-go/pkg"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type ProviderConfig struct {
	MasterSecretKey jwk.Key
	Dst             string
}

func (c *ProviderConfig) GeneratePublicKeys(requestJson []byte) ([]byte, error) {
	// unmarshal request
	var hashSlices []string
	err := json.Unmarshal(requestJson, &hashSlices)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal request %s", err)
	}

	// prepare return item
	keyMap := make(map[string]KeyData)

	// Loop through the slice and fill the map
	for _, hash := range hashSlices {
		// generate key id
		keyID := pkg.GenerateUUID()

		// combine with hash
		context := append([]byte(keyID), hash...)

		// get domain separation tag from config
		dstByte := []byte(c.Dst)

		// derive public key
		derivedSecretKey, err := DeriveSecretKey(c.MasterSecretKey, context, dstByte)
		if err != nil {
			return nil, fmt.Errorf("failed to derive secret key %s", err)
		}

		derivedPublicKey, err := derivedSecretKey.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to get public key %s", err)
		}

		// convert to json bytes
		pubKeyBytes, err := pkg.KeyJWKToJson(derivedPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal jwk to json bytes %w", err)
		}

		// make entry into map
		keyMap[hash] = KeyData{KeyID: keyID, WpPubkey: pubKeyBytes}
	}

	// marshal for transport over http
	keyMapBytes, err := json.Marshal(keyMap)
	if err != nil {
		return nil, err
	}
	return keyMapBytes, nil
}
