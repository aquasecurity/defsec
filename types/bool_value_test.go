package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_BoolValueIsTrue(t *testing.T) {
	testCases := []struct {
		desc     string
		value    bool
		expected bool
	}{
		{
			desc:     "returns true when isTrue",
			value:    true,
			expected: true,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

			val := Bool(tC.value, NewRange("main.tf", 123, 123), &FakeReference{})

			assert.Equal(t, tC.expected, val.IsTrue())
		})
	}
}
