package cvc

import "github.com/lestrrat-go/jwx/v2/jwk"

// MasterKeyStore interface allows users to implement their own key storage
type MasterKeyStore interface {
	GetMasterKey() (jwk.Key, error)
}

// UserData holds user-specific cryptographic material
type UserData struct {
	Email    string
	KeyID    string
	Salt     []byte
	WpPubKey jwk.Key
	VcSecKey jwk.Key
	VcPubKey jwk.Key
}
