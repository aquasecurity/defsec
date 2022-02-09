package cloudfront

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableWaf(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudfront.Cloudfront
		expected bool
	}{
		{
			name: "CloudFront distribution missing WAF",
			input: cloudfront.Cloudfront{
				Metadata: types.NewTestMetadata(),
				Distributions: []cloudfront.Distribution{
					{
						Metadata: types.NewTestMetadata(),
						WAFID:    types.String("", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "CloudFront distribution with WAF provided",
			input: cloudfront.Cloudfront{
				Metadata: types.NewTestMetadata(),
				Distributions: []cloudfront.Distribution{
					{
						Metadata: types.NewTestMetadata(),
						WAFID:    types.String("waf_id", types.NewTestMetadata()),
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
			results := CheckEnableWaf.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableWaf.Rule().LongID() {
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
