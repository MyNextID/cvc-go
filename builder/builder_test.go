package builder

import (
	"encoding/json"
	"testing"
)

func TestPresentation_Create(t *testing.T) {
	t.Run("ValidPresentationWithMultipleGroups", func(t *testing.T) {
		// Create languages
		enLang, err := NewLanguage("en")
		if err != nil {
			t.Fatalf("Failed to create English language: %v", err)
		}
		slLang, err := NewLanguage("sl")
		if err != nil {
			t.Fatalf("Failed to create Slovenian language: %v", err)
		}

		// Create elements for first group
		fullNameElement := Element{
			Titles: map[Language]string{
				*enLang: "Full name",
				*slLang: "Polno ime",
			},
			Multilanguage: false,
			Value:         "/credentialSubject/fullName/en",
		}

		issuedOnElement := Element{
			Titles: map[Language]string{
				*enLang: "Issued on",
				*slLang: "Datum izdaje",
			},
			Multilanguage: false,
			Format:        NewDateTimeFormat(),
			Value:         "/issuanceDate",
		}

		officialNameElement := Element{
			Titles: map[Language]string{
				*enLang: "Official name",
				*slLang: "Uradno ime",
			},
			Multilanguage: true,
			Values: map[Language]string{
				*enLang: "/issuer/legalName/en",
				*slLang: "/issuer/legalName/sl",
			},
		}

		// Create first group
		group1, err := NewGroup(
			[]Element{fullNameElement, issuedOnElement, officialNameElement},
			1,
			map[Language]string{}, // No title for this group
		)
		if err != nil {
			t.Fatalf("Failed to create first group: %v", err)
		}

		// Create elements for second group
		websiteElement := Element{
			Titles: map[Language]string{
				*enLang: "Website",
				*slLang: "Spletna stran",
			},
			Optional:      true,
			Multilanguage: false,
			Value:         "/issuer/homepage/contentURL",
		}

		durationElement := Element{
			Titles: map[Language]string{
				*enLang: "Duration",
				*slLang: "Trajanje v urah",
			},
			Optional:      true,
			Multilanguage: false,
			Format:        NewDurationFormat(),
			Value:         "/credentialSubject/hasClaim/workload",
		}

		// Create second group with title
		group2, err := NewGroup(
			[]Element{websiteElement, durationElement},
			2,
			map[Language]string{
				*enLang: "Activity information",
				*slLang: "Podatki o aktivnosti",
			},
		)
		if err != nil {
			t.Fatalf("Failed to create second group: %v", err)
		}

		// Create presentation
		presentation := &Presentation{
			Languages: []Language{*enLang, *slLang},
			Groups:    []Group{*group1, *group2},
		}

		// Test Create method
		result, err := presentation.Create()
		if err != nil {
			t.Fatalf("presentation.Create() failed: %v", err)
		}

		// Verify it's valid JSON
		var output map[string]interface{}
		if err := json.Unmarshal(result, &output); err != nil {
			t.Fatalf("Result is not valid JSON: %v", err)
		}

		// Verify structure
		languages, ok := output["languages"].([]interface{})
		if !ok {
			t.Errorf("languages field is missing or not an array")
		}
		if len(languages) != 2 {
			t.Errorf("Expected 2 languages, got %d", len(languages))
		}

		groups, ok := output["groups"].([]interface{})
		if !ok {
			t.Errorf("groups field is missing or not an array")
		}
		if len(groups) != 2 {
			t.Errorf("Expected 2 groups, got %d", len(groups))
		}

		t.Logf("Successfully created presentation JSON: %s", string(result))
	})

	t.Run("SingleLanguagePresentation", func(t *testing.T) {
		// Create single language
		enLang, err := NewLanguage("en")
		if err != nil {
			t.Fatalf("Failed to create English language: %v", err)
		}

		// Create simple element
		element := Element{
			Titles: map[Language]string{
				*enLang: "Test Element",
			},
			Multilanguage: false,
			Value:         "/test/path",
		}

		// Create group
		group, err := NewGroup(
			[]Element{element},
			1,
			map[Language]string{},
		)
		if err != nil {
			t.Fatalf("Failed to create group: %v", err)
		}

		// Create presentation
		presentation := &Presentation{
			Languages: []Language{*enLang},
			Groups:    []Group{*group},
		}

		// Test Create method
		result, err := presentation.Create()
		if err != nil {
			t.Fatalf("presentation.Create() failed: %v", err)
		}

		// Verify structure
		var output map[string]interface{}
		if err := json.Unmarshal(result, &output); err != nil {
			t.Fatalf("Result is not valid JSON: %v", err)
		}

		languages := output["languages"].([]interface{})
		if len(languages) != 1 || languages[0] != "en" {
			t.Errorf("Expected single English language, got %v", languages)
		}

		t.Logf("Single language presentation: %s", string(result))
	})

	t.Run("PresentationWithOptionalElements", func(t *testing.T) {
		// Create languages
		enLang, err := NewLanguage("en")
		if err != nil {
			t.Fatalf("Failed to create English language: %v", err)
		}

		// Create optional element
		optionalElement := Element{
			Titles: map[Language]string{
				*enLang: "Optional Field",
			},
			Optional:      true,
			Multilanguage: false,
			Value:         "/optional/field",
		}

		// Create required element
		requiredElement := Element{
			Titles: map[Language]string{
				*enLang: "Required Field",
			},
			Multilanguage: false,
			Value:         "/required/field",
		}

		// Create group
		group, err := NewGroup(
			[]Element{optionalElement, requiredElement},
			1,
			map[Language]string{},
		)
		if err != nil {
			t.Fatalf("Failed to create group: %v", err)
		}

		// Create presentation
		presentation := &Presentation{
			Languages: []Language{*enLang},
			Groups:    []Group{*group},
		}

		// Test Create method
		result, err := presentation.Create()
		if err != nil {
			t.Fatalf("presentation.Create() failed: %v", err)
		}

		// Verify optional field is handled correctly
		var output map[string]interface{}
		if err := json.Unmarshal(result, &output); err != nil {
			t.Fatalf("Result is not valid JSON: %v", err)
		}

		t.Logf("Presentation with optional elements: %s", string(result))
	})

	t.Run("PresentationWithFormats", func(t *testing.T) {
		// Create language
		enLang, err := NewLanguage("en")
		if err != nil {
			t.Fatalf("Failed to create English language: %v", err)
		}

		// Create elements with different formats
		dateTimeElement := Element{
			Titles: map[Language]string{
				*enLang: "Date Time Field",
			},
			Multilanguage: false,
			Format:        NewDateTimeFormat(),
			Value:         "/datetime/field",
		}

		durationElement := Element{
			Titles: map[Language]string{
				*enLang: "Duration Field",
			},
			Multilanguage: false,
			Format:        NewDurationFormat(),
			Value:         "/duration/field",
		}

		noFormatElement := Element{
			Titles: map[Language]string{
				*enLang: "No Format Field",
			},
			Multilanguage: false,
			Value:         "/no/format/field",
		}

		// Create group
		group, err := NewGroup(
			[]Element{dateTimeElement, durationElement, noFormatElement},
			1,
			map[Language]string{},
		)
		if err != nil {
			t.Fatalf("Failed to create group: %v", err)
		}

		// Create presentation
		presentation := &Presentation{
			Languages: []Language{*enLang},
			Groups:    []Group{*group},
		}

		// Test Create method
		result, err := presentation.Create()
		if err != nil {
			t.Fatalf("presentation.Create() failed: %v", err)
		}

		// Parse and verify formats
		var output map[string]interface{}
		if err := json.Unmarshal(result, &output); err != nil {
			t.Fatalf("Result is not valid JSON: %v", err)
		}

		groups := output["groups"].([]interface{})
		group1 := groups[0].(map[string]interface{})
		elements := group1["elements"].([]interface{})

		// Check date-time format
		elem1 := elements[0].(map[string]interface{})
		if elem1["format"] != "date-time" {
			t.Errorf("Expected date-time format, got %v", elem1["format"])
		}

		// Check duration format
		elem2 := elements[1].(map[string]interface{})
		if elem2["format"] != "duration" {
			t.Errorf("Expected duration format, got %v", elem2["format"])
		}

		// Check no format (should not have format field)
		elem3 := elements[2].(map[string]interface{})
		if _, hasFormat := elem3["format"]; hasFormat {
			t.Errorf("Expected no format field, but found one")
		}

		t.Logf("Presentation with formats: %s", string(result))
	})

	t.Run("ErrorCases", func(t *testing.T) {
		// Test invalid language
		invalidLang := Language{Code: "invalid"}
		presentation := &Presentation{
			Languages: []Language{invalidLang},
			Groups:    []Group{},
		}

		_, err := presentation.Create()
		if err == nil {
			t.Errorf("Expected error for invalid language, but got none")
		}
		t.Logf("Correctly rejected invalid language: %v", err)

		// Test element with missing multilanguage values
		enLang, _ := NewLanguage("en")
		slLang, _ := NewLanguage("sl")

		invalidElement := Element{
			Titles: map[Language]string{
				*enLang: "Test",
				*slLang: "Test SL",
			},
			Multilanguage: true,
			Values: map[Language]string{
				*enLang: "/test/en",
				// Missing Slovenian value
			},
		}

		group, _ := NewGroup([]Element{invalidElement}, 1, map[Language]string{})
		presentation = &Presentation{
			Languages: []Language{*enLang, *slLang},
			Groups:    []Group{*group},
		}

		_, err = presentation.Create()
		if err == nil {
			t.Errorf("Expected error for incomplete multilanguage values, but got none")
		}
		t.Logf("Correctly rejected incomplete multilanguage values: %v", err)

		// Test element with missing title languages
		incompleteElement := Element{
			Titles: map[Language]string{
				*enLang: "Test",
				// Missing Slovenian title
			},
			Multilanguage: false,
			Value:         "/test/path",
		}

		group2, _ := NewGroup([]Element{incompleteElement}, 1, map[Language]string{})
		presentation = &Presentation{
			Languages: []Language{*enLang, *slLang},
			Groups:    []Group{*group2},
		}

		_, err = presentation.Create()
		if err == nil {
			t.Errorf("Expected error for missing title languages, but got none")
		}
		t.Logf("Correctly rejected missing title languages: %v", err)
	})

	t.Run("EmptyGroupValidation", func(t *testing.T) {
		enLang, _ := NewLanguage("en")

		// Create group with no elements (should fail during NewGroup)
		_, err := NewGroup([]Element{}, 1, map[Language]string{})
		if err == nil {
			t.Errorf("Expected error for empty group, but got none")
		}
		t.Logf("Correctly rejected empty group: %v", err)

		// Test empty groups array
		presentation := &Presentation{
			Languages: []Language{*enLang},
			Groups:    []Group{},
		}

		result, err := presentation.Create()
		if err != nil {
			t.Fatalf("presentation.Create() failed with empty groups: %v", err)
		}

		var output map[string]interface{}
		if err := json.Unmarshal(result, &output); err != nil {
			t.Fatalf("Result is not valid JSON: %v", err)
		}

		groups := output["groups"].([]interface{})
		if len(groups) != 0 {
			t.Errorf("Expected empty groups array, got %d groups", len(groups))
		}

		t.Logf("Empty groups presentation: %s", string(result))
	})

	t.Run("ComplexMultilanguagePresentation", func(t *testing.T) {
		// Test with multiple languages and complex multilanguage elements
		enLang, _ := NewLanguage("en")
		slLang, _ := NewLanguage("sl")
		deLang, _ := NewLanguage("de")

		// Multilanguage element with all three languages
		multiElement := Element{
			Titles: map[Language]string{
				*enLang: "Multi Language Title",
				*slLang: "Večjezični naslov",
				*deLang: "Mehrsprachiger Titel",
			},
			Multilanguage: true,
			Values: map[Language]string{
				*enLang: "/multi/en",
				*slLang: "/multi/sl",
				*deLang: "/multi/de",
			},
		}

		group, err := NewGroup([]Element{multiElement}, 1, map[Language]string{
			*enLang: "Group Title",
			*slLang: "Naslov skupine",
			*deLang: "Gruppentitel",
		})
		if err != nil {
			t.Fatalf("Failed to create multilingual group: %v", err)
		}

		presentation := &Presentation{
			Languages: []Language{*enLang, *slLang, *deLang},
			Groups:    []Group{*group},
		}

		result, err := presentation.Create()
		if err != nil {
			t.Fatalf("presentation.Create() failed: %v", err)
		}

		var output map[string]interface{}
		if err := json.Unmarshal(result, &output); err != nil {
			t.Fatalf("Result is not valid JSON: %v", err)
		}

		// Verify all three languages are present
		languages := output["languages"].([]interface{})
		if len(languages) != 3 {
			t.Errorf("Expected 3 languages, got %d", len(languages))
		}

		t.Logf("Complex multilanguage presentation: %s", string(result))
	})
}

func TestPresentation_ValidateElement(t *testing.T) {
	enLang, _ := NewLanguage("en")
	slLang, _ := NewLanguage("sl")

	presentation := &Presentation{
		Languages: []Language{*enLang, *slLang},
	}

	t.Run("ValidSingleLanguageElement", func(t *testing.T) {
		element := &Element{
			Titles: map[Language]string{
				*enLang: "Test",
				*slLang: "Test SL",
			},
			Multilanguage: false,
			Value:         "/test/path",
		}

		err := presentation.ValidateElement(element)
		if err != nil {
			t.Errorf("Valid single language element failed validation: %v", err)
		}
	})

	t.Run("ValidMultilanguageElement", func(t *testing.T) {
		element := &Element{
			Titles: map[Language]string{
				*enLang: "Test",
				*slLang: "Test SL",
			},
			Multilanguage: true,
			Values: map[Language]string{
				*enLang: "/test/en",
				*slLang: "/test/sl",
			},
		}

		err := presentation.ValidateElement(element)
		if err != nil {
			t.Errorf("Valid multilanguage element failed validation: %v", err)
		}
	})

	t.Run("InvalidTitleLanguages", func(t *testing.T) {
		deLang, _ := NewLanguage("de")
		element := &Element{
			Titles: map[Language]string{
				*enLang: "Test",
				*deLang: "Test DE", // German not in presentation languages
			},
			Multilanguage: false,
			Value:         "/test/path",
		}

		err := presentation.ValidateElement(element)
		if err == nil {
			t.Errorf("Expected error for mismatched title languages, but got none")
		}
	})

	t.Run("InvalidMultilanguageValues", func(t *testing.T) {
		element := &Element{
			Titles: map[Language]string{
				*enLang: "Test",
				*slLang: "Test SL",
			},
			Multilanguage: true,
			Values: map[Language]string{
				*enLang: "/test/en",
				// Missing Slovenian value
			},
		}

		err := presentation.ValidateElement(element)
		if err == nil {
			t.Errorf("Expected error for incomplete multilanguage values, but got none")
		}
	})
}
