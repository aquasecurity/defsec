package aws

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/stretchr/testify/assert"
)

func TestScanner_GetRegisteredRules(t *testing.T) {
	testCases := []struct {
		name    string
		scanner *Scanner
	}{
		{
			name: "get framework rules",
			scanner: &Scanner{
				frameworks: []framework.Framework{framework.CIS_AWS_1_2},
			},
		},
		{
			name: "get spec rules",
			scanner: &Scanner{
				spec: "awscis1.2",
			},
		},
		{
			name: "invalid spec",
			scanner: &Scanner{
				spec: "invalid spec",
				// we still expect default rules to work
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, i := range tc.scanner.getRegisteredRules() {
				if _, ok := i.Rule().Frameworks[framework.CIS_AWS_1_2]; !ok {
					assert.FailNow(t, "unexpected rule found: ", i.Rule().AVDID, tc.name)
				}
			}
		})
	}
}
