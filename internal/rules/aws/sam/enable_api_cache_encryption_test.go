package sam

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableApiCacheEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "API unencrypted cache data",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: types.NewTestMetadata(),
						RESTMethodSettings: sam.RESTMethodSettings{
							Metadata:           types.NewTestMetadata(),
							CacheDataEncrypted: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API encrypted cache data",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: types.NewTestMetadata(),
						RESTMethodSettings: sam.RESTMethodSettings{
							Metadata:           types.NewTestMetadata(),
							CacheDataEncrypted: types.Bool(true, types.NewTestMetadata()),
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
			testState.AWS.SAM = test.input
			results := CheckEnableApiCacheEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableApiCacheEncryption.Rule().LongID() {
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
