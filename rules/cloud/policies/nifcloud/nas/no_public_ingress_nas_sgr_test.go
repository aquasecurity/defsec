package nas

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/nas"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngressnasSgr(t *testing.T) {
	tests := []struct {
		name     string
		input    nas.NAS
		expected bool
	}{
		{
			name: "NIFCLOUD ingress nas security group rule with wildcard address",
			input: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						CIDRs: []defsecTypes.StringValue{
							defsecTypes.String("0.0.0.0/0", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD ingress nas security group rule with private address",
			input: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						CIDRs: []defsecTypes.StringValue{
							defsecTypes.String("10.0.0.0/16", defsecTypes.NewTestMetadata()),
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
			testState.Nifcloud.NAS = test.input
			results := CheckNoPublicIngressNASSgr.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngressNASSgr.Rule().LongID() {
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
