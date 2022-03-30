package securitycenter

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/securitycenter"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSetRequiredContactDetails(t *testing.T) {
	tests := []struct {
		name     string
		input    securitycenter.SecurityCenter
		expected bool
	}{
		{
			name: "Contact's phone number missing",
			input: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata: types.NewTestMetadata(),
						Phone:    types.String("", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Contact's phone number provided",
			input: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata: types.NewTestMetadata(),
						Phone:    types.String("+1-555-555-5555", types.NewTestMetadata()),
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
			results := CheckSetRequiredContactDetails.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSetRequiredContactDetails.Rule().LongID() {
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
