package parser

import (
	"strconv"

	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/cftypes"

	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

func setPropertyValueFromJson(node jfather.Node, propertyData *PropertyInner) error {

	switch node.Kind() {

	case jfather.KindNumber:
		propertyData.Type = cftypes.Float64
		return node.Decode(&propertyData.Value)
	case jfather.KindBoolean:
		propertyData.Type = cftypes.Bool
		return node.Decode(&propertyData.Value)
	case jfather.KindString:
		propertyData.Type = cftypes.String
		return node.Decode(&propertyData.Value)
	case jfather.KindObject:
		var childData map[string]*Property
		if err := node.Decode(&childData); err != nil {
			return err
		}
		propertyData.Type = cftypes.Map
		propertyData.Value = childData
		return nil
	case jfather.KindArray:
		var childData []*Property
		if err := node.Decode(&childData); err != nil {
			return err
		}
		propertyData.Type = cftypes.List
		propertyData.Value = childData
		return nil
	default:
		propertyData.Type = cftypes.String
		return node.Decode(&propertyData.Value)
	}

}

func setPropertyValueFromYaml(node *yaml.Node, propertyData *PropertyInner) error {
	if IsIntrinsicFunc(node) {
		var newContent []*yaml.Node

		newContent = append(newContent, &yaml.Node{
			Tag:   "!!str",
			Value: getIntrinsicTag(node.Tag),
			Kind:  yaml.ScalarNode,
		})

		newContent = createNode(node, newContent)

		node.Tag = "!!map"
		node.Kind = yaml.MappingNode
		node.Content = newContent
	}

	if node.Content == nil {

		switch node.Tag {

		case "!!int":
			propertyData.Type = cftypes.Int
			propertyData.Value, _ = strconv.Atoi(node.Value)
		case "!!bool":
			propertyData.Type = cftypes.Bool
			propertyData.Value, _ = strconv.ParseBool(node.Value)
		case "!!str", "!!string":
			propertyData.Type = cftypes.String
			propertyData.Value = node.Value
		}
		return nil
	}

	switch node.Tag {
	case "!!map":
		var childData map[string]*Property
		if err := node.Decode(&childData); err != nil {
			return err
		}
		propertyData.Type = cftypes.Map
		propertyData.Value = childData
		return nil
	case "!!seq":
		var childData []*Property
		if err := node.Decode(&childData); err != nil {
			return err
		}
		propertyData.Type = cftypes.List
		propertyData.Value = childData
		return nil
	}

	return nil
}

func createNode(node *yaml.Node, newContent []*yaml.Node) []*yaml.Node {
	if node.Content == nil {
		newContent = append(newContent, &yaml.Node{
			Tag:   "!!str",
			Value: node.Value,
			Kind:  yaml.ScalarNode,
		})
	} else {

		newNode := &yaml.Node{
			Content: node.Content,
			Kind:    node.Kind,
		}

		switch node.Kind {
		case yaml.SequenceNode:
			newNode.Tag = "!!seq"
		case yaml.MappingNode:
			newNode.Tag = "!!map"
		case yaml.ScalarNode:
		default:
			newNode.Tag = node.Tag
		}
		newContent = append(newContent, newNode)
	}
	return newContent
}

func calculateEndLine(node *yaml.Node) int {
	if node.Content == nil {
		return node.Line
	}

	return calculateEndLine(node.Content[len(node.Content)-1])

}
