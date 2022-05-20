package emr

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/emr"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/stretchr/testify/assert"
)

func TestEnableAtRestEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    emr.EMR
		expected bool
	}{
		{
			name: "EMR cluster with at-rest encryption enabled",
			input: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Name: types.String("test", types.NewTestMetadata()),
						Configuration: types.String(`{
							"EncryptionConfiguration": {
							  "AtRestEncryptionConfiguration": {
								"S3EncryptionConfiguration": {
								  "EncryptionMode": "SSE-S3"
								},
								"LocalDiskEncryptionConfiguration": {
								  "EncryptionKeyProviderType": "AwsKms",
								  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
								}
							  },
							  "EnableInTransitEncryption": true,
							  "EnableAtRestEncryption": true
							}
						  }`, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "EMR cluster with at-rest encryption disabled",
			input: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Name: types.String("test", types.NewTestMetadata()),
						Configuration: types.String(`{
							"EncryptionConfiguration": {
							  "AtRestEncryptionConfiguration": {
								"S3EncryptionConfiguration": {
								  "EncryptionMode": "SSE-S3"
								},
								"LocalDiskEncryptionConfiguration": {
								  "EncryptionKeyProviderType": "AwsKms",
								  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
								}
							  },
							  "EnableInTransitEncryption": false,
							  "EnableAtRestEncryption": false
							}
						  }`, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.EMR = test.input
			results := CheckEnableAtRestEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAtRestEncryption.Rule().LongID() {
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

// func TestCheckEnableInTransitEncryption(t *testing.T) {
// 	tests := []struct {
// 		name     string
// 		input    emr.EMR
// 		expected bool
// 	}{
// 		{
// 			name: "EMR cluster with in-transit encryption disabled",
// 			input: emr.EMR{
// 				SecurityConfiguration: []emr.SecurityConfiguration{
// 					{
// 						Metadata:                  types.NewTestMetadata(),
// 						EnableInTransitEncryption: types.Bool(false, types.NewTestMetadata()),
// 					},
// 				},
// 			},
// 			expected: true,
// 		},
// 		{
// 			name: "Emr cluster with in-transit encryption enabled",
// 			input: emr.EMR{
// 				SecurityConfiguration: []emr.SecurityConfiguration{
// 					{
// 						Metadata:                  types.NewTestMetadata(),
// 						EnableInTransitEncryption: types.Bool(true, types.NewTestMetadata()),
// 					},
// 				},
// 			},
// 			expected: false,
// 		},
// 	}
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			var testState state.State
// 			testState.AWS.EMR = test.input
// 			results := CheckEnableAtRestEncryption.Evaluate(&testState)
// 			var found bool
// 			for _, result := range results {
// 				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAtRestEncryption.Rule().LongID() {
// 					found = true
// 				}
// 			}
// 			if test.expected {
// 				assert.True(t, found, "Rule should have been found")
// 			} else {
// 				assert.False(t, found, "Rule should not have been found")
// 			}
// 		})
// 	}
// }
