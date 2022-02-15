package elasticache

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/elasticache"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableInTransitEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    elasticache.ElastiCache
		expected bool
	}{
		{
			name: "ElastiCache replication group with in-transit encryption disabled",
			input: elasticache.ElastiCache{
				Metadata: types.NewTestMetadata(),
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                 types.NewTestMetadata(),
						TransitEncryptionEnabled: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "ElastiCache replication group with in-transit encryption enabled",
			input: elasticache.ElastiCache{
				Metadata: types.NewTestMetadata(),
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                 types.NewTestMetadata(),
						TransitEncryptionEnabled: types.Bool(true, types.NewTestMetadata()),
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
			results := CheckEnableInTransitEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableInTransitEncryption.Rule().LongID() {
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
