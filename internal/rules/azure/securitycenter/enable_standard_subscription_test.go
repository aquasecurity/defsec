package securitycenter

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/securitycenter"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStandardSubscription(t *testing.T) {
	tests := []struct {
		name     string
		input    securitycenter.SecurityCenter
		expected bool
	}{
		{
			name: "Security center set with free subscription",
			input: securitycenter.SecurityCenter{
				Subscriptions: []securitycenter.SubscriptionPricing{
					{
						Metadata: types.NewTestMetadata(),
						Tier:     types.String(securitycenter.TierFree, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Security center set with standard subscription",
			input: securitycenter.SecurityCenter{
				Subscriptions: []securitycenter.SubscriptionPricing{
					{
						Metadata: types.NewTestMetadata(),
						Tier:     types.String(securitycenter.TierStandard, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.SecurityCenter = test.input
			results := CheckEnableStandardSubscription.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableStandardSubscription.Rule().LongID() {
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
