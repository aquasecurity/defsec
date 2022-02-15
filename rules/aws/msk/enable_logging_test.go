package msk

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/msk"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    msk.MSK
		expected bool
	}{
		{
			name: "Cluster with logging disabled",
			input: msk.MSK{
				Metadata: types.NewTestMetadata(),
				Clusters: []msk.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: types.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: types.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: types.NewTestMetadata(),
									Enabled:  types.Bool(false, types.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: types.NewTestMetadata(),
									Enabled:  types.Bool(false, types.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: types.NewTestMetadata(),
									Enabled:  types.Bool(false, types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster logging to S3",
			input: msk.MSK{
				Metadata: types.NewTestMetadata(),
				Clusters: []msk.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: types.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: types.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: types.NewTestMetadata(),
									Enabled:  types.Bool(true, types.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: types.NewTestMetadata(),
									Enabled:  types.Bool(false, types.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: types.NewTestMetadata(),
									Enabled:  types.Bool(false, types.NewTestMetadata()),
								},
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
			testState.AWS.MSK = test.input
			results := CheckEnableLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableLogging.Rule().LongID() {
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
