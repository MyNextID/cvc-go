package builder

import (
	"fmt"

	"github.com/emvi/iso-639-1"
)

type Language struct {
	code string
}

// NewLanguage creates a new Language with validation
func NewLanguage(code string) (*Language, error) {
	if !iso6391.ValidCode(code) {
		return nil, fmt.Errorf("invalid ISO 639-1 language code: %s", code)
	}
	return &Language{code: code}, nil
}

func (l Language) IsValid() bool {
	return iso6391.ValidCode(l.code)
}

func (l Language) GetName() string {
	return iso6391.Name(l.code)
}

// Validate validates the language code and returns an error if invalid
func (l Language) Validate() error {
	if !l.IsValid() {
		return fmt.Errorf("invalid ISO 639-1 language code: %s", l.code)
	}
	return nil
}
