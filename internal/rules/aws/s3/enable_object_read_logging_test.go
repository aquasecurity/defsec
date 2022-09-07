package s3

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableObjectReadLogging(t *testing.T) {
	tests := []struct {
		name       string
		s3         s3.S3
		cloudtrail cloudtrail.CloudTrail
		expected   bool
	}{
		{
			name: "S3 bucket with no cloudtrail logging",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("test-bucket", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 bucket with WriteOnly cloudtrail logging (all of s3)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("test-bucket", defsecTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      defsecTypes.NewTestMetadata(),
								ReadWriteType: defsecTypes.String("WriteOnly", defsecTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Type:     defsecTypes.String("AWS::S3::Object", defsecTypes.NewTestMetadata()),
										Values: []defsecTypes.StringValue{
											defsecTypes.String("arn:aws:s3", defsecTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 bucket with ReadOnly cloudtrail logging (all of s3)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("test-bucket", defsecTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      defsecTypes.NewTestMetadata(),
								ReadWriteType: defsecTypes.String("ReadOnly", defsecTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Type:     defsecTypes.String("AWS::S3::Object", defsecTypes.NewTestMetadata()),
										Values: []defsecTypes.StringValue{
											defsecTypes.String("arn:aws:s3", defsecTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (all of s3)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("test-bucket", defsecTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      defsecTypes.NewTestMetadata(),
								ReadWriteType: defsecTypes.String("All", defsecTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Type:     defsecTypes.String("AWS::S3::Object", defsecTypes.NewTestMetadata()),
										Values: []defsecTypes.StringValue{
											defsecTypes.String("arn:aws:s3", defsecTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only this bucket)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("test-bucket", defsecTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      defsecTypes.NewTestMetadata(),
								ReadWriteType: defsecTypes.String("All", defsecTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Type:     defsecTypes.String("AWS::S3::Object", defsecTypes.NewTestMetadata()),
										Values: []defsecTypes.StringValue{
											defsecTypes.String("arn:aws:s3:::test-bucket/", defsecTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only another bucket)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("test-bucket", defsecTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      defsecTypes.NewTestMetadata(),
								ReadWriteType: defsecTypes.String("All", defsecTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Type:     defsecTypes.String("AWS::S3::Object", defsecTypes.NewTestMetadata()),
										Values: []defsecTypes.StringValue{
											defsecTypes.String("arn:aws:s3:::test-bucket2/", defsecTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (this bucket, missing slash)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("test-bucket", defsecTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      defsecTypes.NewTestMetadata(),
								ReadWriteType: defsecTypes.String("All", defsecTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Type:     defsecTypes.String("AWS::S3::Object", defsecTypes.NewTestMetadata()),
										Values: []defsecTypes.StringValue{
											defsecTypes.String("arn:aws:s3:::test-bucket", defsecTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.S3 = test.s3
			testState.AWS.CloudTrail = test.cloudtrail
			results := CheckEnableObjectReadLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableObjectReadLogging.Rule().LongID() {
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
