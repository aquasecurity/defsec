package stringFunctions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Concatenation(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "simple string concatenation",
			args: []interface{}{
				"hello",
				", ",
				"world",
				"!",
			},
			expected: "hello, world!",
		},
		{
			name: "string concatenation with non strings",
			args: []interface{}{
				"pi to 3 decimal places is ",
				3.142,
			},
			expected: "pi to 3 decimal places is 3.142",
		},
		{
			name: "string concatenation with multiple primitives",
			args: []interface{}{
				"to say that ",
				3,
				" is greater than ",
				5,
				" would be ",
				false,
			},
			expected: "to say that 3 is greater than 5 would be false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			concatenated := Concat(tt.args...)
			require.Equal(t, tt.expected, concatenated)
		})
	}
}
