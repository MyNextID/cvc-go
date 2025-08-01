package cvc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/MyNextID/cvc-go/pkg"
)

type IssuerConfig struct {
	WpGeneratePublicKeysURL string
	WpGenerateSecretKeysURL string
}

// F0 generates wallet provider public keys for a map of users
func (c *IssuerConfig) GetPublicKeysFromWalletProvider(emailMap map[string]string) (map[string]*UserData, error) {
	// Input validation
	if len(emailMap) == 0 {
		return nil, fmt.Errorf("emailMap cannot be nil or empty")
	}

	// Initialize return map
	tempMap := make(map[string]*UserData)

	// initialize hash -> uuid map
	hashUuidMap := map[string]string{}

	// initialize slice for wp
	var hashSlices []string

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

		// combine email with salt
		data := append([]byte(email), salt...)

		// hash the combined data
		hashed := pkg.Hash(data)

		// convert to base64
		base64Hash := base64.StdEncoding.EncodeToString(hashed)

		// add hash to slice for wp
		hashSlices = append(hashSlices, base64Hash)

		// update hash uuid map
		hashUuidMap[base64Hash] = uuid
	}

	// marshal the hashSlice to json for transport
	hashBytes, err := json.Marshal(hashSlices)
	if err != nil {
		panic(err)
	}

	// call api to get public keys for users
	receivedMap, err := c.GeneratePublicKeys(hashBytes)
	if err != nil {
		return nil, fmt.Errorf("failed get public keys from wallet provider: %s", err)
	}

	// loop through the map and fill out the return map
	for hash, data := range receivedMap {
		// figure out to which user the data belongs
		userId := hashUuidMap[hash]
		// set values for user in return map
		tempMap[userId].KeyID = data.KeyID
		// for the key we need to convert it to jwk.Key from json bytes
		wpPubKey, err := pkg.KeyJsonToJWK(data.WpPubkey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert json formatted key to jwk.Key: %s", err)
		}
		tempMap[userId].WpPubKey = wpPubKey
	}

	return tempMap, nil
}

func (c *IssuerConfig) GeneratePublicKeys(hashBytes []byte) (map[string]KeyData, error) {
	// Build the HTTP POST request with JSON body
	req, err := http.NewRequest("POST", c.WpGeneratePublicKeysURL, bytes.NewBuffer(hashBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %s", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Send the HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get response from wp: %s", err)
	}
	defer resp.Body.Close()

	// Check for non-200 response codes
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Non-OK HTTP status: %d. Body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %s", err)
	}

	// unmarshall response in to map
	var receivedMap map[string]KeyData
	err = json.Unmarshal(body, &receivedMap)
	if err != nil {
		return nil, err
	}
	return receivedMap, err
}

// F1 generates VC keys and adds confirmation key to the VC payload
func (c *IssuerConfig) AddCnfToPayload(uuid string, vcPayload map[string]interface{}, userMap map[string]*UserData) error {
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
	vcSecretKey, err := GenerateSecretKey()
	if err != nil {
		return fmt.Errorf("failed to generate VC secret key for user %s: %w", uuid, err)
	}

	// Extract public key from the secret key
	vcPublicKey, err := vcSecretKey.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to extract VC public key JWK for user %s: %w", uuid, err)
	}

	// Store keys in user data
	userData.VcSecKey = vcSecretKey
	userData.VcPubKey = vcPublicKey

	// Generate confirmation key by adding VC public key + WP public key
	cnfKey, err := AddPublicKeys(userData.VcPubKey, userData.WpPubKey)
	if err != nil {
		return fmt.Errorf("failed to generate confirmation key for user %s: %w", uuid, err)
	}

	// Add confirmation key to VC payload
	if err := pkg.AddKeyToPayload(vcPayload, cnfKey); err != nil {
		return fmt.Errorf("failed to add confirmation key to payload for user %s: %w", uuid, err)
	}

	return nil
}

// F2 encrypts the credential with credential public key and encrypts the credential secret key
// with wallet provider public key. It returns the message pack to be send to the credential
// recipient email
func (c *IssuerConfig) PrepareMessagePack(signedCredential []byte, uuid string, userMap map[string]*UserData, displayConf []byte) ([]byte, error) {
	// initialize message pack
	msgPack := &MessagePack{
		WpGenerateSecretKeysURL: c.WpGeneratePublicKeysURL,
		KeyId:                   userMap[uuid].KeyID,
		Salt:                    userMap[uuid].Salt,
		Email:                   userMap[uuid].Email,
		DisplayMap:              displayConf,
	}
	// encrypt credential
	encVC, err := pkg.EncryptWithPublicKey(signedCredential, userMap[uuid].VcPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt credential %w", err)
	}
	// add to pack
	msgPack.EncVC = encVC

	// encrypt credential secret key
	// first convert to bytes
	vcSecBytes, err := pkg.KeyJWKToJson(userMap[uuid].VcSecKey)
	if err != nil {
		log.Fatalf("Failed to convert secret key to bytes %v", err)
		return nil, err
	}
	encVCSecKey, err := pkg.EncryptWithPublicKey(vcSecBytes, userMap[uuid].WpPubKey)
	if err != nil {
		log.Fatalf("Failed to encrypt vc secret key %v", err)
		return nil, err
	}
	// add to pack
	msgPack.EncVCSecKey = encVCSecKey

	// 	// convert pack to json (for now; final version will have a dedicated format)
	msgPackBytes, err := json.Marshal(msgPack)
	if err != nil {
		log.Fatalf("failed to marshal MessagePack: %v", err)
		return nil, err
	}

	return msgPackBytes, nil
}
