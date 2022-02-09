package eks

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/eks"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptSecrets(t *testing.T) {
	tests := []struct {
		name     string
		input    eks.EKS
		expected bool
	}{
		{
			name: "EKS Cluster with no secrets in the resources attribute",
			input: eks.EKS{
				Metadata: types.NewTestMetadata(),
				Clusters: []eks.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: types.NewTestMetadata(),
							Secrets:  types.Bool(false, types.NewTestMetadata()),
							KMSKeyID: types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS Cluster with secrets in the resources attribute but no KMS key",
			input: eks.EKS{
				Metadata: types.NewTestMetadata(),
				Clusters: []eks.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: types.NewTestMetadata(),
							Secrets:  types.Bool(true, types.NewTestMetadata()),
							KMSKeyID: types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS Cluster with secrets in the resources attribute and a KMS key",
			input: eks.EKS{
				Metadata: types.NewTestMetadata(),
				Clusters: []eks.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: types.NewTestMetadata(),
							Secrets:  types.Bool(true, types.NewTestMetadata()),
							KMSKeyID: types.String("some-arn", types.NewTestMetadata()),
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
			testState.AWS.EKS = test.input
			results := CheckEncryptSecrets.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEncryptSecrets.Rule().LongID() {
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
