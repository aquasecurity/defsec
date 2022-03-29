package sam

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckApiUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "SAM API TLS v1.0",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				APIs: []sam.API{
					{
						Metadata: types.NewTestMetadata(),
						DomainConfiguration: sam.DomainConfiguration{
							Metadata:       types.NewTestMetadata(),
							SecurityPolicy: types.String("TLS_1_0", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "SAM API TLS v1.2",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				APIs: []sam.API{
					{
						Metadata: types.NewTestMetadata(),
						DomainConfiguration: sam.DomainConfiguration{
							Metadata:       types.NewTestMetadata(),
							SecurityPolicy: types.String("TLS_1_2", types.NewTestMetadata()),
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
			testState.AWS.SAM = test.input
			results := CheckApiUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckApiUseSecureTlsPolicy.Rule().LongID() {
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
