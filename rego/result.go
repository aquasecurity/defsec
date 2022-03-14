package rego

import (
	"fmt"
	"strconv"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/rules"
	"github.com/open-policy-agent/opa/rego"
)

type regoResult struct {
	Filepath  string
	StartLine int
	EndLine   int
	Message   string
}

func (r regoResult) GetMetadata() types.Metadata {
	rng := types.NewRange(r.Filepath, r.StartLine, r.EndLine)
	return types.NewMetadata(
		rng,
		types.NewNamedReference(rng.String()),
	)
}

func (r regoResult) GetRawValue() interface{} {
	return nil
}

func parseResult(raw interface{}) (*regoResult, error) {
	var result regoResult
	switch val := raw.(type) {
	case string:
		result.Message = val
	case map[string]interface{}:
		result.Message = fmt.Sprintf("%s", val["msg"])
		result.Filepath = fmt.Sprintf("%s", val["filepath"])
		result.StartLine = parseLineNumber(val["startline"])
		result.EndLine = parseLineNumber(val["endline"])
	default:
		return nil, fmt.Errorf("invalid result type: %#v", raw)
	}
	return &result, nil
}

func parseLineNumber(raw interface{}) int {
	str := fmt.Sprintf("%s", raw)
	n, _ := strconv.Atoi(str)
	return n
}

func (s *Scanner) convertResults(set rego.ResultSet) rules.Results {
	var results rules.Results
	for _, result := range set {
		for _, expression := range result.Expressions {
			values, ok := expression.Value.([]interface{})
			if !ok {
				continue
			}

			for _, value := range values {
				regoResult, err := parseResult(value)
				if err != nil {
					// TODO: handle
					continue
				}
				results.Add(regoResult.Message, regoResult)
			}
		}
	}
	return results
}

func (s *Scanner) embellishResultsWithRuleMetadata(results rules.Results, metadata StaticMetadata) rules.Results {
	// TODO: improve this conversion
	results.SetRule(metadata.ToRule())
	return results
}
