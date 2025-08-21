package builder

import "fmt"

type Element struct {
	// Titles is a required field.
	// It is required to have the same length of titles as there are languages in the presentation.
	Titles map[Language]string

	// Optional defines if the Element is an optional field - which means it could have empty values.
	Optional bool

	// Format is not a required field.
	// There is no default value.
	Format ElementFormat

	// Multilanguage is not a required field.
	// Default value is false.
	Multilanguage bool

	// Value is a required field if Multilanguage is set to false.
	// It requires a pointer to a field in payload.
	//
	// Example value would be "/issuanceDate"
	Value string

	// Values is a required field if Multilanguage is set to true.
	// It requires a pointer to a field in payload.
	//
	// Example value for en would be "/issuer/legalName/en"
	Values map[Language]string
}

func (e *Element) NewElement(titles map[Language]string) (*Element, error) {
	if len(titles) == 0 {
		return nil, fmt.Errorf("title(s) are required when creating a new element")
	}

	return &Element{
		Titles:        titles,
		Multilanguage: false,
	}, nil
}

func (p *Presentation) ValidateElement(element *Element) error {
	titleOK := element.TitleContainsAllLanguages(p.Languages)
	if !titleOK {
		return fmt.Errorf("title languages on element do not match languages on the presentation")
	}

	if element.Multilanguage {
		valuesOK := element.VerifyMultiLangValues(p.Languages)
		if !valuesOK {
			return fmt.Errorf("element is multilang and the element values are either empty or do not match languages on the presentation")
		}
	} else {
		// Check if element.Value is set
		if element.Value == "" {
			return fmt.Errorf("element is not multilang and the element value is an empty string - not allowed")
		}
	}

	return nil
}

func (e *Element) TitleContainsAllLanguages(existingLanguages []Language) bool {
	for _, existingLang := range existingLanguages {
		if _, exists := e.Titles[existingLang]; !exists {
			return false
		}
	}
	return true
}

func (e *Element) VerifyMultiLangValues(existingLanguages []Language) bool {
	for _, existingLang := range existingLanguages {
		value, exists := e.Values[existingLang]
		if !exists || value == "" {
			return false
		}
	}
	return true
}
