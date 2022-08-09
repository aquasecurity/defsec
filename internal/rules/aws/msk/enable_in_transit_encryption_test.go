package msk

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/msk"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				Clusters: []msk.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     defsecTypes.NewTestMetadata(),
							ClientBroker: defsecTypes.String(msk.ClientBrokerEncryptionPlaintext, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster client broker with plaintext or TLS encryption",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     defsecTypes.NewTestMetadata(),
							ClientBroker: defsecTypes.String(msk.ClientBrokerEncryptionTLSOrPlaintext, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster client broker with TLS encryption",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     defsecTypes.NewTestMetadata(),
							ClientBroker: defsecTypes.String(msk.ClientBrokerEncryptionTLS, defsecTypes.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableInTransitEncryption.Rule().LongID() {
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
