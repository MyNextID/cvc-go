package cvc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/MyNextID/cvc-go/pkg"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// F0 generates wallet provider public keys for a map of users
func (c *Config) F0(emailMap map[string]string) (map[string]*UserData, error) {
	// Input validation
	if emailMap == nil || len(emailMap) == 0 {
		return nil, fmt.Errorf("emailMap cannot be nil or empty")
	}

	// Get master key from the store
	masterKey, err := c.MasterKeyStore.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get master key: %w", err)
	}

	// Initialize return map
	tempMap := make(map[string]*UserData)

	// Process each user
	for uuid, email := range emailMap {
		if email == "" {
			return nil, fmt.Errorf("email cannot be empty for uuid: %s", uuid)
		}

		// Initialize UserData
		tempMap[uuid] = &UserData{Email: email}

		// Generate 32-byte random salt
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt for user %s: %w", uuid, err)
		}
		tempMap[uuid].Salt = salt

		// Generate key ID
		keyID := pkg.GenerateUUID()
		tempMap[uuid].KeyID = keyID

		// Combine email with salt and hash
		data := append([]byte(email), salt...)
		hashed := pkg.Hash(data)
		base64Hash := base64.StdEncoding.EncodeToString(hashed)

		// Create context for key derivation (keyID + hash)
		context := append([]byte(keyID), base64Hash...)

		// Derive wallet provider key pair
		derivedSecretKey, err := c.DeriveSecretKey(masterKey, context, c.CredentialKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive secret key for user %s: %w", uuid, err)
		}

		// Extract public key
		var privateKey ecdsa.PrivateKey
		if err := derivedSecretKey.Raw(&privateKey); err != nil {
			return nil, fmt.Errorf("failed to extract private key for user %s: %w", uuid, err)
		}

		wpPubKey, err := jwk.FromRaw(&privateKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create public key JWK for user %s: %w", uuid, err)
		}

		tempMap[uuid].WpPubKey = wpPubKey
	}

	return tempMap, nil
}

// F1 generates VC keys and adds confirmation key to the VC payload
func (c *Config) F1(uuid string, vcPayload map[string]interface{}, userMap map[string]*UserData) error {
	// Input validation
	if uuid == "" {
		return fmt.Errorf("uuid cannot be empty")
	}
	if vcPayload == nil {
		return fmt.Errorf("vcPayload cannot be nil")
	}
	if userMap == nil {
		return fmt.Errorf("userMap cannot be nil")
	}

	userData, exists := userMap[uuid]
	if !exists {
		return fmt.Errorf("user data not found for uuid: %s", uuid)
	}
	if userData.WpPubKey == nil {
		return fmt.Errorf("wallet provider public key not set for user: %s", uuid)
	}

	// Generate VC secret key
	vcSecretKey, err := c.GenerateSecretKey()
	if err != nil {
		return fmt.Errorf("failed to generate VC secret key for user %s: %w", uuid, err)
	}

	// Extract public key from the secret key
	var vcPrivateKey ecdsa.PrivateKey
	if err := vcSecretKey.Raw(&vcPrivateKey); err != nil {
		return fmt.Errorf("failed to extract VC private key for user %s: %w", uuid, err)
	}

	vcPublicKey, err := jwk.FromRaw(&vcPrivateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to create VC public key JWK for user %s: %w", uuid, err)
	}

	// Store keys in user data
	userData.VcSecKey = vcSecretKey
	userData.VcPubKey = vcPublicKey

	// Generate confirmation key by adding VC public key + WP public key
	cnfKey, err := c.AddPublicKeys(userData.VcPubKey, userData.WpPubKey)
	if err != nil {
		return fmt.Errorf("failed to generate confirmation key for user %s: %w", uuid, err)
	}

	// Add confirmation key to VC payload
	if err := pkg.AddKeyToPayload(vcPayload, cnfKey); err != nil {
		return fmt.Errorf("failed to add confirmation key to payload for user %s: %w", uuid, err)
	}

	return nil
}
