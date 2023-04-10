package computing

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/computing"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoCommonPrivateInstance(t *testing.T) {
	tests := []struct {
		name     string
		input    computing.Computing
		expected bool
	}{
		{
			name: "NIFCLOUD instance with common private",
			input: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkInterfaces: []computing.NetworkInterface{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								NetworkID: defsecTypes.String("net-COMMON_PRIVATE", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD instance with private LAN",
			input: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkInterfaces: []computing.NetworkInterface{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								NetworkID: defsecTypes.String("net-some-private-lan", defsecTypes.NewTestMetadata()),
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
			results := CheckNoCommonPrivateInstance.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoCommonPrivateInstance.Rule().LongID() {
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
