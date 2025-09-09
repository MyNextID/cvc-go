package builder

import (
	"encoding/json"
	"fmt"
)

// FormatType represents the type of format for an element
type FormatType string

const (
	FormatDateTime FormatType = "date-time"
	FormatDuration FormatType = "duration"
	FormatJPEG     FormatType = "jpeg"
	FormatPNG      FormatType = "png"
)

// ElementFormat represents the format configuration for an element
type ElementFormat struct {
	Type FormatType `json:"-"` // Don't serialize this field
}

// NewJpegFormat creates a new format for displaying base64 jpeg image
func NewJpegFormat() ElementFormat {
	return ElementFormat{Type: FormatJPEG}
}

// NewPngFormat creates a new format for displaying base64 png image
func NewPngFormat() ElementFormat {
	return ElementFormat{Type: FormatPNG}
}

// NewDateTimeFormat creates a new DateTime format
func NewDateTimeFormat() ElementFormat {
	return ElementFormat{Type: FormatDateTime}
}

// NewDurationFormat creates a new Duration format
func NewDurationFormat() ElementFormat {
	return ElementFormat{Type: FormatDuration}
}

// MarshalJSON implements json.Marshaler interface
// This ensures that ElementFormat serializes as a simple string value
func (f *ElementFormat) MarshalJSON() ([]byte, error) {
	if f.Type == "" {
		return json.Marshal(nil)
	}
	return json.Marshal(string(f.Type))
}

// UnmarshalJSON implements json.Unmarshaler interface
func (f *ElementFormat) UnmarshalJSON(data []byte) error {
	var formatStr string
	if err := json.Unmarshal(data, &formatStr); err != nil {
		return fmt.Errorf("failed to unmarshal format: %w", err)
	}
	f.Type = FormatType(formatStr)
	return nil
}

// IsEmpty returns true if the format is not set
func (f *ElementFormat) IsEmpty() bool {
	return f.Type == ""
}

// String returns the string representation of the format
func (f *ElementFormat) String() string {
	return string(f.Type)
}
