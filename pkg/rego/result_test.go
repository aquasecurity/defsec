package rego

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseResult(t *testing.T) {
	var testCases = []struct {
		name  string
		input interface{}
		want  regoResult
	}{
		{
			name:  "unknown",
			input: nil,
			want: regoResult{
				Managed: true,
				Message: "Rego policy resulted in DENY",
			},
		},
		{
			name:  "string",
			input: "message",
			want: regoResult{
				Managed: true,
				Message: "message",
			},
		},
		{
			name:  "strings",
			input: []interface{}{"message"},
			want: regoResult{
				Managed: true,
				Message: "message",
			},
		},
		{
			name: "slice",
			input: []interface{}{
				"message",
				map[string]interface{}{
					"filepath": "a.out",
				},
			},
			want: regoResult{
				Managed:  true,
				Message:  "message",
				Filepath: "a.out",
			},
		},
		{
			name: "legacy",
			input: map[string]interface{}{
				"msg":          "message",
				"filepath":     "a.out",
				"fskey":        "abcd",
				"resource":     "resource",
				"startline":    "123",
				"endline":      "456",
				"sourceprefix": "git",
				"explicit":     true,
				"managed":      true,
			},
			want: regoResult{
				Message:      "message",
				Filepath:     "a.out",
				Resource:     "resource",
				StartLine:    123,
				EndLine:      456,
				SourcePrefix: "git",
				FSKey:        "abcd",
				Explicit:     true,
				Managed:      true,
			},
		},
		{
			name: "with parent",
			input: map[string]any{
				"msg": "message",
				"metadata": map[string]any{
					"filepath":     "a.out",
					"fskey":        "abcd",
					"resource":     "resource",
					"startline":    "123",
					"endline":      "456",
					"sourceprefix": "git",
					"explicit":     true,
					"managed":      true,
					"parent": map[string]any{
						"__defsec_metadata": map[string]any{
							"filepath":     "parent-a.out",
							"fskey":        "parent-abcd",
							"resource":     "parent-resource",
							"startline":    "234",
							"endline":      "345",
							"sourceprefix": "parent-git",
							"explicit":     true,
							"managed":      true,
						},
					},
				},
			},
			want: regoResult{
				Filepath:     "a.out",
				FSKey:        "abcd",
				Resource:     "resource",
				StartLine:    123,
				EndLine:      456,
				SourcePrefix: "git",
				Explicit:     true,
				Managed:      true,
				Message:      "message",
				Parent: &regoResult{
					Filepath:     "parent-a.out",
					FSKey:        "parent-abcd",
					Resource:     "parent-resource",
					StartLine:    234,
					EndLine:      345,
					SourcePrefix: "parent-git",
					Explicit:     true,
					Managed:      true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have := parseResult(tc.input)
			assert.NotNil(t, have)
			assert.Equal(t, tc.want, *have)
		})
	}
}
