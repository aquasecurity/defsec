package elasticsearch

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/elasticsearch"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    elasticsearch.Elasticsearch
		expected bool
	}{
		{
			name: "Elasticsearch domain with TLS v1.0",
			input: elasticsearch.Elasticsearch{
				Metadata: types.NewTestMetadata(),
				Domains: []elasticsearch.Domain{
					{
						Metadata: types.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:  types.NewTestMetadata(),
							TLSPolicy: types.String("Policy-Min-TLS-1-0-2019-07", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Elasticsearch domain with TLS v1.2",
			input: elasticsearch.Elasticsearch{
				Metadata: types.NewTestMetadata(),
				Domains: []elasticsearch.Domain{
					{
						Metadata: types.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:  types.NewTestMetadata(),
							TLSPolicy: types.String("Policy-Min-TLS-1-2-2019-07", types.NewTestMetadata()),
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
			results := CheckUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckUseSecureTlsPolicy.Rule().LongID() {
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
