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

type KeyData struct {
	KeyID    string `json:"key_id"`
	WpPubkey []byte `json:"wp_pubkey"`
}

// MessagePack - todo define its final form
type MessagePack struct {
	EncVC       []byte `json:"encrypted_vc" msgpack:"encrypted_vc"`                 // encrypted with VcPubKey
	EncVCSecKey []byte `json:"encrypted_vc_sec_key" msgpack:"encrypted_vc_sec_key"` // encrypted with WpPubKey
	ProviderURL string `json:"provider_url" msgpack:"provider_url"`                 // so you know which wp to call
	KeyId       string `json:"key_id" msgpack:"key_id"`                             // needed to generate wp secret key
	Salt        []byte `json:"salt" msgpack:"salt"`                                 // needed to generate wp secret key
	Email       string `json:"email" msgpack:"email"`                               // who gets the VC
	DisplayMap  []byte `json:"display_map" msgpack:"display_map"`                   // how VC looks in wallet
}

type SecretKeyData struct {
	KeyId string `json:"key_id"`
	Salt  []byte `json:"salt"`
	Email string `json:"email"`
}
