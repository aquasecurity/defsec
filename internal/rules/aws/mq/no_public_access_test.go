package mq

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/mq"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    mq.MQ
		expected bool
	}{
		{
			name: "AWS MQ Broker with public access enabled",
			input: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata:     types2.NewTestMetadata(),
						PublicAccess: types2.Bool(true, types2.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS MQ Broker with public access disabled",
			input: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata:     types2.NewTestMetadata(),
						PublicAccess: types2.Bool(false, types2.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.MQ = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
