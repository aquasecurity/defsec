package functions

import "testing"

func Test_CopyIndex(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected int
	}{
		{
			name:     "CopyIndex with 1",
			args:     []interface{}{},
			expected: 1,
		},
		{
			name:     "CopyIndex with 2",
			args:     []interface{}{},
			expected: 2,
		},
		{
			name:     "CopyIndex with 3",
			args:     []interface{}{},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CopyIndex(tt.args...)
			if got != tt.expected {
				t.Errorf("CopyIndex() = %v, want %v", got, tt.expected)
			}
		})
	}
}
