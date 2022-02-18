package cloudfront

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceHttps(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudfront.Cloudfront
		expected bool
	}{
		{
			name: "CloudFront distribution default cache behaviour with allow all policy",
			input: cloudfront.Cloudfront{
				Metadata: types.NewTestMetadata(),
				Distributions: []cloudfront.Distribution{
					{
						Metadata: types.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             types.NewTestMetadata(),
							ViewerProtocolPolicy: types.String(cloudfront.ViewerPolicyProtocolAllowAll, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "CloudFront distribution ordered cache behaviour with allow all policy",
			input: cloudfront.Cloudfront{
				Metadata: types.NewTestMetadata(),
				Distributions: []cloudfront.Distribution{
					{
						Metadata: types.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             types.NewTestMetadata(),
							ViewerProtocolPolicy: types.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, types.NewTestMetadata()),
						},
						OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
							{
								Metadata:             types.NewTestMetadata(),
								ViewerProtocolPolicy: types.String(cloudfront.ViewerPolicyProtocolAllowAll, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "CloudFront distribution cache behaviours allowing HTTPS only",
			input: cloudfront.Cloudfront{
				Metadata: types.NewTestMetadata(),
				Distributions: []cloudfront.Distribution{
					{
						Metadata: types.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             types.NewTestMetadata(),
							ViewerProtocolPolicy: types.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, types.NewTestMetadata()),
						},
						OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
							{
								Metadata:             types.NewTestMetadata(),
								ViewerProtocolPolicy: types.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, types.NewTestMetadata()),
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
			testState.AWS.Cloudfront = test.input
			results := CheckEnforceHttps.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnforceHttps.Rule().LongID() {
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
