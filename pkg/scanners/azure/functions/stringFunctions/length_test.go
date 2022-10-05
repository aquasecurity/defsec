package stringFunctions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Length(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected int
	}{
		{
			name: "length of a string",
			args: []interface{}{
				"hello",
			},
			expected: 5,
		},
		{
			name: "length of an empty string",
			args: []interface{}{
				"",
			},
			expected: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Length(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
