package builder

type Element struct {
	// Titles is a required field.
	Titles map[Language]string

	// Format is not a required field.
	// There is no default value.
	Format ElementFormat

	// Multilanguage is not a required field.
	// Default value is false.
	Multilanguage bool

	// Value os a required field if Multilanguage is set to false.
	// It requires a pointer to a field in payload.
	// Example value would be "/issuanceDate"
	Value string

	// Values is a required field if Multilanguage is set to true.
	// It requires a pointer to a field in payload.
	// Example value for en would be "/issuer/legalName/en"
	Values map[Language]string
}
