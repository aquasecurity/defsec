package functions

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_UTCNow(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "utc now day",
			args: []interface{}{
				"d",
			},
			expected: fmt.Sprintf("%d", time.Now().Day()),
		},
		{
			name: "utc now date",
			args: []interface{}{
				"yyyy-M-d",
			},
			expected: fmt.Sprintf("%d-%d-%d", time.Now().Year(), time.Now().Month(), time.Now().Day()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := UTCNow(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
