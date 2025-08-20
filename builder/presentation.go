package builder

import (
	"encoding/json"
	"fmt"
)

type Presentation struct {
	Languages []Language
	Groups    []Group
}

func (p *Presentation) Create() ([]byte, error) {
	// Step 1: Validation
	if err := p.validate(); err != nil {
		return nil, err
	}

	// Step 2: Build the output structure
	output := p.buildOutput()

	// Step 3: Marshal to JSON
	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal presentation to JSON: %w", err)
	}

	return jsonBytes, nil
}

func (p *Presentation) validate() error {
	// Validate languages
	for _, lang := range p.Languages {
		if !lang.IsValid() {
			return fmt.Errorf("language: %v is not valid", lang)
		}
	}

	// Validate groups and elements consistency
	for _, group := range p.Groups {
		err := group.Validate()
		if err != nil {
			return err
		}

		// Validate elements multilanguage requirements
		for _, element := range group.Elements {
			// Skip validation if optional
			if element.Optional {
				continue
			}

			err = p.ValidateElement(&element)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *Presentation) buildOutput() map[string]interface{} {
	// Define output structures that match the JSON schema
	type OutputElement struct {
		Title         map[string]string `json:"title"`
		Multilanguage bool              `json:"multilanguage,omitzero"`
		Optional      bool              `json:"optional,omitzero"`
		Format        string            `json:"format,omitzero"`
		Value         string            `json:"value,omitzero"`
		Values        map[string]string `json:"values,omitzero"`
	}

	type OutputGroup struct {
		ID       uint              `json:"id"`
		Title    map[string]string `json:"title,omitzero"`
		Elements []OutputElement   `json:"elements"`
	}

	type OutputPresentation struct {
		Languages []string      `json:"languages"`
		Groups    []OutputGroup `json:"groups"`
	}

	// Transform languages
	languages := make([]string, len(p.Languages))
	for i, lang := range p.Languages {
		languages[i] = lang.Code
	}

	// Transform groups
	groups := make([]OutputGroup, len(p.Groups))
	for i, group := range p.Groups {
		outputGroup := OutputGroup{
			ID:       group.ID,
			Elements: make([]OutputElement, len(group.Elements)),
		}

		// Only set title if it's not empty
		if len(group.Titles) != 0 {
			// Create title map for all languages with the same title
			// Note: The current Group struct only has a single Title string,
			// but the JSON examples show title as a language map.
			// This might need adjustment based on your actual requirements.
			titleMap := make(map[string]string)
			for _, lang := range p.Languages {
				titleMap[lang.Code] = group.Titles[lang]
			}
			outputGroup.Title = titleMap
		}

		// Transform elements
		for j, element := range group.Elements {
			outputElement := OutputElement{
				Title:         make(map[string]string),
				Multilanguage: element.Multilanguage,
				Optional:      element.Optional,
			}

			// Transform titles
			for lang, title := range element.Titles {
				outputElement.Title[lang.Code] = title
			}

			// Set format if not empty
			if !element.Format.IsEmpty() {
				outputElement.Format = element.Format.String()
			}

			// Set value or values based on multilanguage flag
			if element.Multilanguage {
				outputElement.Values = make(map[string]string)
				for lang, value := range element.Values {
					outputElement.Values[lang.Code] = value
				}
			} else {
				outputElement.Value = element.Value
			}

			outputGroup.Elements[j] = outputElement
		}

		groups[i] = outputGroup
	}

	// Create the final output structure
	output := OutputPresentation{
		Languages: languages,
		Groups:    groups,
	}

	// Convert to map[string]interface{} for JSON marshaling
	result := make(map[string]interface{})
	result["languages"] = output.Languages
	result["groups"] = output.Groups

	return result
}
