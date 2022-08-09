package iam

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoRootAccessKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "root user without access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("root", types2.NewTestMetadata()),
						AccessKeys: nil,
					},
				},
			},
			expected: false,
		},
		{
			name: "other user without access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("other", types2.NewTestMetadata()),
						AccessKeys: nil,
					},
				},
			},
			expected: false,
		},
		{
			name: "other user with access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: types2.NewTestMetadata(),
						Name:     types2.String("other", types2.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     types2.NewTestMetadata(),
								AccessKeyId:  types2.String("BLAH", types2.NewTestMetadata()),
								Active:       types2.Bool(true, types2.NewTestMetadata()),
								CreationDate: types2.TimeUnresolvable(types2.NewTestMetadata()),
								LastAccess:   types2.TimeUnresolvable(types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "root user with inactive access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: types2.NewTestMetadata(),
						Name:     types2.String("root", types2.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     types2.NewTestMetadata(),
								AccessKeyId:  types2.String("BLAH", types2.NewTestMetadata()),
								Active:       types2.Bool(false, types2.NewTestMetadata()),
								CreationDate: types2.TimeUnresolvable(types2.NewTestMetadata()),
								LastAccess:   types2.TimeUnresolvable(types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "root user with active access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: types2.NewTestMetadata(),
						Name:     types2.String("root", types2.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     types2.NewTestMetadata(),
								AccessKeyId:  types2.String("BLAH", types2.NewTestMetadata()),
								Active:       types2.Bool(true, types2.NewTestMetadata()),
								CreationDate: types2.TimeUnresolvable(types2.NewTestMetadata()),
								LastAccess:   types2.TimeUnresolvable(types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := checkNoRootAccessKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkNoRootAccessKeys.Rule().LongID() {
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
