package elasticache

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticache"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableBackupRetention(t *testing.T) {
	tests := []struct {
		name     string
		input    elasticache.ElastiCache
		expected bool
	}{
		{
			name: "Cluster snapshot retention days set to 0",
			input: elasticache.ElastiCache{
				Clusters: []elasticache.Cluster{
					{
						Metadata:               types.NewTestMetadata(),
						Engine:                 types.String("redis", types.NewTestMetadata()),
						NodeType:               types.String("cache.m4.large", types.NewTestMetadata()),
						SnapshotRetentionLimit: types.Int(0, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster snapshot retention days set to 5",
			input: elasticache.ElastiCache{
				Clusters: []elasticache.Cluster{
					{
						Metadata:               types.NewTestMetadata(),
						Engine:                 types.String("redis", types.NewTestMetadata()),
						NodeType:               types.String("cache.m4.large", types.NewTestMetadata()),
						SnapshotRetentionLimit: types.Int(5, types.NewTestMetadata()),
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
			results := CheckEnableBackupRetention.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableBackupRetention.Rule().LongID() {
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
