package computing

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/computing"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngressSgr(t *testing.T) {
	tests := []struct {
		name     string
		input    computing.Computing
		expected bool
	}{
		{
			name: "NIFCLOUD ingress security group rule with wildcard address",
			input: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								CIDR:     defsecTypes.String("0.0.0.0/0", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD ingress security group rule with private address",
			input: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								CIDR:     defsecTypes.String("10.0.0.0/16", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.Computing = test.input
			results := CheckNoPublicIngressSgr.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngressSgr.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
