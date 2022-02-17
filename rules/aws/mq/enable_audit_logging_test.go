package mq

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/mq"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAuditLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    mq.MQ
		expected bool
	}{
		{
			name: "AWS MQ Broker without audit logging",
			input: mq.MQ{
				Metadata: types.NewTestMetadata(),
				Brokers: []mq.Broker{
					{
						Metadata: types.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: types.NewTestMetadata(),
							Audit:    types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS MQ Broker with audit logging",
			input: mq.MQ{
				Metadata: types.NewTestMetadata(),
				Brokers: []mq.Broker{
					{
						Metadata: types.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: types.NewTestMetadata(),
							Audit:    types.Bool(true, types.NewTestMetadata()),
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
			testState.AWS.MQ = test.input
			results := CheckEnableAuditLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableAuditLogging.Rule().LongID() {
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
