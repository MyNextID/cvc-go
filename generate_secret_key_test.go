package cvc

import (
	"testing"
)

func TestGenerateSecretKey(t *testing.T) {
	config := Config{}
	secretKey, err := config.GenerateSecretKey()
	if err != nil {
		t.Fatalf("GenerateSecretKey returned an error: %v", err)
	}
	t.Logf("CVC library GenerateSecretKey result: %s", secretKey)
}
