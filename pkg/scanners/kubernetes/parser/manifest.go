package parser

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type Manifest struct {
	Path    string
	Content ManifestNode
}

func (m *Manifest) UnmarshalYAML(value *yaml.Node) error {

	switch value.Tag {
	case "!!map":
		node := make(ManifestNode)
		if err := value.Decode(&node); err != nil {
			return err
		}
		m.Content = node
	default:
		return fmt.Errorf("failed to handle tag: %s", value.Tag)
	}

	return nil
}

func (m *Manifest) ToRegoMap() map[string]interface{} {
	return m.Content
}
