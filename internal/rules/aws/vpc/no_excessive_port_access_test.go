package vpc

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/vpc"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoExcessivePortAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    vpc.VPC
		expected bool
	}{
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: vpc.VPC{
				NetworkACLs: []vpc.NetworkACL{
					{
						Metadata: types.NewTestMetadata(),
						Rules: []vpc.NetworkACLRule{
							{
								Metadata: types.NewTestMetadata(),
								Protocol: types.String("-1", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: vpc.VPC{
				NetworkACLs: []vpc.NetworkACL{
					{
						Metadata: types.NewTestMetadata(),
						Rules: []vpc.NetworkACLRule{
							{
								Metadata: types.NewTestMetadata(),
								Protocol: types.String("all", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with tcp protocol",
			input: vpc.VPC{
				NetworkACLs: []vpc.NetworkACL{
					{
						Metadata: types.NewTestMetadata(),
						Rules: []vpc.NetworkACLRule{
							{
								Metadata: types.NewTestMetadata(),
								Protocol: types.String("tcp", types.NewTestMetadata()),
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
			testState.AWS.VPC = test.input
			results := CheckNoExcessivePortAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoExcessivePortAccess.Rule().LongID() {
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
