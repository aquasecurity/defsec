package msk

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/msk"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableInTransitEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    msk.MSK
		expected bool
	}{
		{
			name: "Cluster client broker with plaintext encryption",
			input: msk.MSK{
				Metadata: types.NewTestMetadata(),
				Clusters: []msk.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     types.NewTestMetadata(),
							ClientBroker: types.String(msk.ClientBrokerEncryptionPlaintext, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster client broker with plaintext or TLS encryption",
			input: msk.MSK{
				Metadata: types.NewTestMetadata(),
				Clusters: []msk.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     types.NewTestMetadata(),
							ClientBroker: types.String(msk.ClientBrokerEncryptionTLSOrPlaintext, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster client broker with TLS encryption",
			input: msk.MSK{
				Metadata: types.NewTestMetadata(),
				Clusters: []msk.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     types.NewTestMetadata(),
							ClientBroker: types.String(msk.ClientBrokerEncryptionTLS, types.NewTestMetadata()),
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
			testState.AWS.MSK = test.input
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
