package util

import (
	"encoding/json"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"gopkg.in/yaml.v3"
)

// GetJsonBytes ...
func GetJsonBytes(policyProp *parser.Property, format parser.SourceFormat) []byte {
	lines, err := policyProp.AsRawStrings()
	if err != nil {
		return nil
	}
	if format == parser.JsonSourceFormat {
		return []byte(strings.Join(lines, " "))
	}

	lines = removeLeftMargin(lines)

	yamlContent := strings.Join(lines, "\n")
	var body interface{}
	if err := yaml.Unmarshal([]byte(yamlContent), &body); err != nil {
		return nil
	}
	jsonBody := convert(body)
	policyJson, err := json.Marshal(jsonBody)
	if err != nil {
		return nil
	}
	return policyJson

}

func removeLeftMargin(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	prefixSpace := len(lines[0]) - len(strings.TrimLeft(lines[0], " "))

	for i, line := range lines {
		lines[i] = line[prefixSpace:]
	}
	return lines
}

func convert(input interface{}) interface{} {
	switch x := input.(type) {
	case map[interface{}]interface{}:
		outpMap := map[string]interface{}{}
		for k, v := range x {
			outpMap[k.(string)] = convert(v)
		}
		return outpMap
	case []interface{}:
		for i, v := range x {
			x[i] = convert(v)
		}
	}
	return input
}
