package rego

import (
	"fmt"
	"io/fs"
	"strconv"

	"github.com/aquasecurity/defsec/pkg/scan"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/open-policy-agent/opa/rego"
)

const denyMessage = "Rego policy resulted in DENY"

type regoResult struct {
	Filepath     string
	Resource     string
	StartLine    int
	EndLine      int
	SourcePrefix string
	Message      string
	Explicit     bool
	Managed      bool
	FSKey        string
	FS           fs.FS
	Parent       *regoResult
}

func messageResult(msg string) *regoResult {
	return &regoResult{
		Managed: true,
		Message: msg,
	}
}

func (r regoResult) GetMetadata() defsecTypes.Metadata {
	var m defsecTypes.Metadata
	if !r.Managed {
		m = defsecTypes.NewUnmanagedMetadata()
	} else {
		rng := defsecTypes.NewRangeWithFSKey(r.Filepath, r.StartLine, r.EndLine, r.SourcePrefix, r.FSKey, r.FS)
		if r.Explicit {
			m = defsecTypes.NewExplicitMetadata(rng, r.Resource)
		} else {
			m = defsecTypes.NewMetadata(rng, r.Resource)
		}
	}
	if r.Parent != nil {
		return m.WithParent(r.Parent.GetMetadata())
	}
	return m
}

func (r regoResult) GetRawValue() interface{} {
	return nil
}

func (r *regoResult) applyOffset(offset int) {
	r.StartLine += offset
	r.EndLine += offset
}

func (r *regoResult) updateMeta(raw map[string]any) {
	for k, v := range raw {
		switch k {
		case "startline", "StartLine":
			r.StartLine = parseLineNumber(v)
		case "endline", "EndLine":
			r.EndLine = parseLineNumber(v)
		case "filepath", "Path":
			r.Filepath = getString(v)
		case "sourceprefix":
			r.SourcePrefix = getString(v)
		case "explicit":
			r.Explicit = getBool(v)
		case "managed":
			r.Managed = getBool(v)
		case "fskey":
			r.FSKey = getString(v)
		case "resource":
			r.Resource = getString(v)
		}
	}
}

func getString(raw any) string {
	if str, ok := raw.(string); ok {
		return str
	}
	return ""
}

func getBool(raw any) bool {
	if b, ok := raw.(bool); ok {
		return b
	}
	return false
}

func newRegoResult(rawInput any) *regoResult {
	result := &regoResult{
		Managed: true,
	}

	input, ok := rawInput.(map[string]any)
	if !ok {
		return result
	}

	if rawMsg, exists := input["msg"]; exists {
		if msg, ok := rawMsg.(string); ok {
			result.Message = msg
		}
	}

	meta := parseMetadata(input)
	result.updateMeta(meta)

	if parent, ok := meta["parent"]; ok {
		result.Parent = newRegoResult(map[string]any{"metadata": parent})
	}

	return result
}

func parseMetadata(input map[string]any) map[string]any {
	res := make(map[string]any)
	rawMetadata, exists := input["metadata"]
	if !exists {
		// for backward compatibility
		rawMetadata = input
	}

	cause, ok := rawMetadata.(map[string]any)
	if !ok {
		return res
	}

	rawDefsecMeta, exists := cause["__defsec_metadata"]
	if !exists {
		res = cause
	} else {
		defsecMeta, ok := rawDefsecMeta.(map[string]any)
		if !ok {
			return res
		}
		res = defsecMeta
	}

	return res
}

func parseResult(raw any) *regoResult {

	switch val := raw.(type) {
	case []any:
		var msg string
		var result *regoResult
		for _, item := range val {
			switch raw := item.(type) {
			case map[string]any:
				if res := newRegoResult(raw); res != nil {
					result = res
				}
			case string:
				msg = raw
			}
		}
		if result != nil {
			result.Message = msg
			return result
		}
		return messageResult(msg)
	case string:
		return messageResult(val)
	case map[string]any:
		return newRegoResult(val)
	default:
		return messageResult(denyMessage)
	}
}

func parseLineNumber(raw any) int {
	n, _ := strconv.Atoi(fmt.Sprintf("%s", raw))
	return n
}

func (s *Scanner) convertResults(set rego.ResultSet, input Input, namespace string, rule string, traces []string) scan.Results {
	var results scan.Results

	offset := input.GetOffset()

	for _, result := range set {
		for _, expression := range result.Expressions {
			values, ok := expression.Value.([]any)
			if !ok {
				values = []any{expression.Value}
			}
			for _, value := range values {
				regoResult := parseResult(value)
				regoResult.FS = input.FS
				if regoResult.Filepath == "" && input.Path != "" {
					regoResult.Filepath = input.Path
				}
				if regoResult.Message == "" {
					regoResult.Message = fmt.Sprintf("Rego policy rule: %s.%s", namespace, rule)
				}
				regoResult.applyOffset(offset)
				results.AddRego(regoResult.Message, namespace, rule, traces, regoResult)
			}
		}
	}
	return results
}
