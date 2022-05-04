package parser

import (
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
)

const (
	StartLine = "startline"
	EndLine   = "endline"
	Value     = "value"
)

const (
	TagBool   = "!!bool"
	TagInt    = "!!int"
	TagString = "!!str"
	TagSlice  = "!!seq"
	TagMap    = "!!map"
)

type ManifestNode map[string]interface{}

func (r ManifestNode) Value() interface{} {
	if val, ok := r[Value]; ok {
		return val
	}
	return r
}

func (r ManifestNode) StartLine() int {
	if val, ok := r[StartLine]; ok {
		return val.(int)
	}
	return 0
}

func (r ManifestNode) EndLine() int {
	if val, ok := r[EndLine]; ok {
		return val.(int)
	}
	return 0
}

func (r ManifestNode) UnmarshalYAML(node *yaml.Node) error {

	switch node.Tag {
	case TagString:
		if err := r.decodeString(node); err != nil {
			return err
		}
	case TagInt:
		if err := r.decodeInt(node); err != nil {
			return err
		}
	case TagBool:
		if err := r.decodeBool(node); err != nil {
			return err
		}
	case TagMap:
		if err := r.decodeMap(node); err != nil {
			return err
		}
	case TagSlice:
		if err := r.decodeSlice(node); err != nil {
			return err
		}
	default:
		return fmt.Errorf("node tag is not supported %s", node.Tag)
	}

	return nil
}

func (r ManifestNode) decodeString(node *yaml.Node) error {
	r[StartLine] = node.Line
	r[EndLine] = node.Line
	r[Value] = node.Value
	return nil
}

func (r ManifestNode) decodeInt(node *yaml.Node) error {
	r[StartLine] = node.Line
	r[EndLine] = node.Line
	if val, err := strconv.Atoi(node.Value); err != nil {
		return err
	} else {
		r[Value] = val
	}
	return nil
}

func (r ManifestNode) decodeBool(node *yaml.Node) error {
	r[StartLine] = node.Line
	r[EndLine] = node.Line
	if val, err := strconv.ParseBool(node.Value); err != nil {
		return err
	} else {
		r[Value] = val
	}
	return nil
}

func (r ManifestNode) decodeSlice(node *yaml.Node) error {
	var nodes []ManifestNode
	for _, contentNode := range node.Content {
		newNode := make(ManifestNode)
		if err := contentNode.Decode(&newNode); err != nil {
			return err
		}
		nodes = append(nodes, newNode)
	}
	r[StartLine] = node.Line - 1
	r[EndLine] = node.Line
	r[Value] = nodes
	return nil
}

func (r ManifestNode) decodeMap(node *yaml.Node) error {
	var key string
	for i, contentNode := range node.Content {
		if i == 0 || i%2 == 0 {

			key = contentNode.Value
		} else {
			newNode := make(ManifestNode)
			if err := contentNode.Decode(&newNode); err != nil {
				return err
			}
			r[key] = newNode.Value()
			r[StartLine] = node.Line - 1
			r[EndLine] = newNode.EndLine()

			r[fmt.Sprintf("%s__%s", key, StartLine)] = newNode.StartLine()
			r[fmt.Sprintf("%s__%s", key, EndLine)] = newNode.EndLine()
		}
	}
	return nil
}
