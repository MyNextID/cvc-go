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
	if err := p.validate(); err != nil {
		return nil, err
	}

	output := p.buildOutput()

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal presentation to JSON: %w", err)
	}

	return jsonBytes, nil
}

func (p *Presentation) validate() error {
	for _, lang := range p.Languages {
		if !lang.IsValid() {
			return fmt.Errorf("language: %v is not valid", lang)
		}
	}

	for _, group := range p.Groups {
		err := group.Validate()
		if err != nil {
			return err
		}

		for _, element := range group.Elements {
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

	languages := make([]string, len(p.Languages))
	for i, lang := range p.Languages {
		languages[i] = lang.Code
	}

	groups := make([]OutputGroup, len(p.Groups))
	for i, group := range p.Groups {
		outputGroup := OutputGroup{
			ID:       group.ID,
			Elements: make([]OutputElement, len(group.Elements)),
		}

		if len(group.Titles) != 0 {
			titleMap := make(map[string]string)
			for _, lang := range p.Languages {
				titleMap[lang.Code] = group.Titles[lang]
			}
			outputGroup.Title = titleMap
		}

		for j, element := range group.Elements {
			outputElement := OutputElement{
				Title:         make(map[string]string),
				Multilanguage: element.Multilanguage,
				Optional:      element.Optional,
			}

			for lang, title := range element.Titles {
				outputElement.Title[lang.Code] = title
			}

			if !element.Format.IsEmpty() {
				outputElement.Format = element.Format.String()
			}

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

	output := OutputPresentation{
		Languages: languages,
		Groups:    groups,
	}

	result := make(map[string]interface{})
	result["languages"] = output.Languages
	result["groups"] = output.Groups

	return result
}
