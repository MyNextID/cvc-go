package builder

import "fmt"

type Group struct {
	ID       uint
	Titles   map[Language]string
	Elements []Element
}

// NewGroup creates a new Group with validation
func NewGroup(elements []Element, id uint, titles map[Language]string) (*Group, error) {
	if len(elements) == 0 {
		return nil, fmt.Errorf("requires atleast one element in a group")
	}

	if len(titles) == 0 {
		return &Group{
			ID:       id,
			Elements: elements,
		}, nil
	}

	return &Group{
		ID:       id,
		Titles:   titles,
		Elements: elements,
	}, nil
}

func (g *Group) Validate() error {
	if len(g.Elements) == 0 {
		return fmt.Errorf("requires atleast one element in a group with id: %v", g.ID)
	}

	return nil
}
