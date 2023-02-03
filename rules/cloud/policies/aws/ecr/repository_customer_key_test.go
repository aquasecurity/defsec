package ecr

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ecr"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRepositoryCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    ecr.ECR
		expected bool
	}{
		{
			name: "ECR repository not using KMS encryption",
			input: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: defsecTypes.NewTestMetadata(),
							Type:     defsecTypes.String(ecr.EncryptionTypeAES256, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "ECR repository using KMS encryption but missing key",
			input: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: defsecTypes.NewTestMetadata(),
							Type:     defsecTypes.String(ecr.EncryptionTypeKMS, defsecTypes.NewTestMetadata()),
							KMSKeyID: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "ECR repository encrypted with KMS key",
			input: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: defsecTypes.NewTestMetadata(),
							Type:     defsecTypes.String(ecr.EncryptionTypeKMS, defsecTypes.NewTestMetadata()),
							KMSKeyID: defsecTypes.String("some-kms-key", defsecTypes.NewTestMetadata()),
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
			testState.AWS.ECR = test.input
			results := CheckRepositoryCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRepositoryCustomerKey.Rule().LongID() {
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
