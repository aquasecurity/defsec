package elasticache

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/elasticache"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckAddDescriptionForSecurityGroup(t *testing.T) {
	tests := []struct {
		name     string
		input    elasticache.ElastiCache
		expected bool
	}{
		{
			name: "ElastiCache security group with no description provided",
			input: elasticache.ElastiCache{
				Metadata: types.NewTestMetadata(),
				SecurityGroups: []elasticache.SecurityGroup{
					{
						Metadata:    types.NewTestMetadata(),
						Description: types.String("", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "ElastiCache security group with description",
			input: elasticache.ElastiCache{
				Metadata: types.NewTestMetadata(),
				SecurityGroups: []elasticache.SecurityGroup{
					{
						Metadata:    types.NewTestMetadata(),
						Description: types.String("some decent description", types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.ElastiCache = test.input
			results := CheckAddDescriptionForSecurityGroup.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckAddDescriptionForSecurityGroup.Rule().LongID() {
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
