package msk

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/msk"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				Clusters: []msk.Cluster{
					{
						Metadata: types2.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: types2.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: types2.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: types2.NewTestMetadata(),
									Enabled:  types2.Bool(false, types2.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: types2.NewTestMetadata(),
									Enabled:  types2.Bool(false, types2.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: types2.NewTestMetadata(),
									Enabled:  types2.Bool(false, types2.NewTestMetadata()),
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
				Clusters: []msk.Cluster{
					{
						Metadata: types2.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: types2.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: types2.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: types2.NewTestMetadata(),
									Enabled:  types2.Bool(true, types2.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: types2.NewTestMetadata(),
									Enabled:  types2.Bool(false, types2.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: types2.NewTestMetadata(),
									Enabled:  types2.Bool(false, types2.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableLogging.Rule().LongID() {
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
