package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/stretchr/testify/assert"
)

func Test_Reset(t *testing.T) {
	rule := scan.Rule{}
	_ = Register(rule, nil)
	assert.Equal(t, 1, len(GetFrameworkRules()))
	Reset()
	assert.Equal(t, 0, len(GetFrameworkRules()))
}

func Test_Registration(t *testing.T) {
	var tests = []struct {
		name                 string
		registeredFrameworks []framework.Framework
		inputFrameworks      []framework.Framework
		expected             bool
	}{
		{
			name:     "rule without framework specified should be returned when no frameworks are requested",
			expected: true,
		},
		{
			name:            "rule without framework specified should not be returned when a specific framework is requested",
			inputFrameworks: []framework.Framework{framework.CISC},
			expected:        false,
		},
		{
			name:            "rule without framework specified should be returned when the default framework is requested",
			inputFrameworks: []framework.Framework{framework.Default},
			expected:        true,
		},
		{
			name:                 "rule with default framework specified should be returned when the default framework is requested",
			registeredFrameworks: []framework.Framework{framework.Default},
			inputFrameworks:      []framework.Framework{framework.Default},
			expected:             true,
		},
		{
			name:                 "rule with default framework specified should not be returned when a specific framework is requested",
			registeredFrameworks: []framework.Framework{framework.Default},
			inputFrameworks:      []framework.Framework{framework.CISC},
			expected:             false,
		},
		{
			name:                 "rule with specific framework specified should not be returned when a default framework is requested",
			registeredFrameworks: []framework.Framework{framework.CISC},
			inputFrameworks:      []framework.Framework{framework.Default},
			expected:             false,
		},
		{
			name:                 "rule with specific framework specified should be returned when the specific framework is requested",
			registeredFrameworks: []framework.Framework{framework.CISC},
			inputFrameworks:      []framework.Framework{framework.CISC},
			expected:             true,
		},
		{
			name:                 "rule with multiple frameworks specified should be returned when the specific framework is requested",
			registeredFrameworks: []framework.Framework{framework.CISC, "blah"},
			inputFrameworks:      []framework.Framework{framework.CISC},
			expected:             true,
		},
		{
			name:                 "rule with multiple frameworks specified should be returned only once when multiple matching frameworks are requested",
			registeredFrameworks: []framework.Framework{framework.CISC, "blah", "something"},
			inputFrameworks:      []framework.Framework{framework.CISC, "blah", "other"},
			expected:             true,
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			Reset()
			rule := scan.Rule{
				AVDID:      fmt.Sprintf("%d-%s", i, test.name),
				Frameworks: test.registeredFrameworks,
			}
			_ = Register(rule, nil)
			var found bool
			for _, matchedRule := range GetFrameworkRules(test.inputFrameworks...) {
				if matchedRule.Rule().AVDID == rule.AVDID {
					assert.False(t, found, "rule should not be returned more than once")
					found = true
				}
			}
			assert.Equal(t, test.expected, found, "rule should be returned if it matches any of the input frameworks")
		})
	}
}

func Test_Deregistration(t *testing.T) {
	Reset()
	registrationA := Register(scan.Rule{
		AVDID: "A",
	}, nil)
	registrationB := Register(scan.Rule{
		AVDID: "B",
	}, nil)
	assert.Equal(t, 2, len(GetFrameworkRules()))
	Deregister(registrationA)
	actual := GetFrameworkRules()
	require.Equal(t, 1, len(actual))
	assert.Equal(t, "B", actual[0].Rule().AVDID)
	Deregister(registrationB)
	assert.Equal(t, 0, len(GetFrameworkRules()))
}

func Test_DeregistrationMultipleFrameworks(t *testing.T) {
	Reset()
	registrationA := Register(scan.Rule{
		AVDID: "A",
	}, nil)
	registrationB := Register(scan.Rule{
		AVDID:      "B",
		Frameworks: []framework.Framework{"a", "b", "c", framework.Default},
	}, nil)
	assert.Equal(t, 2, len(GetFrameworkRules()))
	Deregister(registrationA)
	actual := GetFrameworkRules()
	require.Equal(t, 1, len(actual))
	assert.Equal(t, "B", actual[0].Rule().AVDID)
	Deregister(registrationB)
	assert.Equal(t, 0, len(GetFrameworkRules()))
}
