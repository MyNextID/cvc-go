package builder

import (
	"fmt"

	"github.com/emvi/iso-639-1"
)

type Language struct {
	Code string
}

// NewLanguage creates a new Language with validation
func NewLanguage(code string) (*Language, error) {
	if !iso6391.ValidCode(code) {
		return nil, fmt.Errorf("invalid ISO 639-1 language Code: %s", code)
	}
	return &Language{Code: code}, nil
}

func (l Language) IsValid() bool {
	return iso6391.ValidCode(l.Code)
}

func (l Language) GetName() string {
	return iso6391.Name(l.Code)
}

// Validate validates the language Code and returns an error if invalid
func (l Language) Validate() error {
	if !l.IsValid() {
		return fmt.Errorf("invalid ISO 639-1 language Code: %s", l.Code)
	}
	return nil
}
