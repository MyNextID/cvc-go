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

// message pack is yet to be defined in its final form
type MessagePack struct {
	EncVC                   []byte // encrypted with VcPubKey
	EncVCSecKey             []byte // encrypted with WpPubKey
	WpGenerateSecretKeysURL string // so you know which wp to call
	KeyId                   string // needed to generate wp secret key
	Salt                    []byte // needed to generate wp secret key
	Email                   string // who gets the VC
	DisplayMap              []byte // how VC looks in wallet
}
