package cloudfront

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudfront.Cloudfront
		expected bool
	}{
		{
			name: "CloudFront distribution using TLS v1.0",
			input: cloudfront.Cloudfront{
				Metadata: types.NewTestMetadata(),
				Distributions: []cloudfront.Distribution{
					{
						Metadata: types.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:               types.NewTestMetadata(),
							MinimumProtocolVersion: types.String("TLSv1.0", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "CloudFront distribution using TLS v1.2",
			input: cloudfront.Cloudfront{
				Metadata: types.NewTestMetadata(),
				Distributions: []cloudfront.Distribution{
					{
						Metadata: types.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:               types.NewTestMetadata(),
							MinimumProtocolVersion: types.String(cloudfront.ProtocolVersionTLS1_2, types.NewTestMetadata()),
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
			results := CheckUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUseSecureTlsPolicy.Rule().LongID() {
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
