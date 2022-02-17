package elasticsearch

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableInTransitEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    elasticsearch.Elasticsearch
		expected bool
	}{
		{
			name: "Elasticsearch domain without in-transit encryption",
			input: elasticsearch.Elasticsearch{
				Metadata: types.NewTestMetadata(),
				Domains: []elasticsearch.Domain{
					{
						Metadata: types.NewTestMetadata(),
						TransitEncryption: elasticsearch.TransitEncryption{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Elasticsearch domain with in-transit encryption",
			input: elasticsearch.Elasticsearch{
				Metadata: types.NewTestMetadata(),
				Domains: []elasticsearch.Domain{
					{
						Metadata: types.NewTestMetadata(),
						TransitEncryption: elasticsearch.TransitEncryption{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
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
			testState.AWS.Elasticsearch = test.input
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
