package iam

import (
	"testing"
	"time"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUnusedCredentialsDisabled(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "User logged in today",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("user", types2.NewTestMetadata()),
						LastAccess: types2.Time(time.Now(), types2.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "User never logged in, but used access key today",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("user", types2.NewTestMetadata()),
						LastAccess: types2.TimeUnresolvable(types2.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     types2.NewTestMetadata(),
								AccessKeyId:  types2.String("AKIACKCEVSQ6C2EXAMPLE", types2.NewTestMetadata()),
								Active:       types2.Bool(true, types2.NewTestMetadata()),
								CreationDate: types2.Time(time.Now().Add(-time.Hour*24*30), types2.NewTestMetadata()),
								LastAccess:   types2.Time(time.Now(), types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "User logged in 100 days ago",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("user", types2.NewTestMetadata()),
						LastAccess: types2.Time(time.Now().Add(-time.Hour*24*100), types2.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "User last used access key 100 days ago but it is no longer active",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("user", types2.NewTestMetadata()),
						LastAccess: types2.TimeUnresolvable(types2.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     types2.NewTestMetadata(),
								AccessKeyId:  types2.String("AKIACKCEVSQ6C2EXAMPLE", types2.NewTestMetadata()),
								Active:       types2.Bool(false, types2.NewTestMetadata()),
								CreationDate: types2.Time(time.Now().Add(-time.Hour*24*120), types2.NewTestMetadata()),
								LastAccess:   types2.Time(time.Now().Add(-time.Hour*24*100), types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "User last used access key 100 days ago and it is active",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("user", types2.NewTestMetadata()),
						LastAccess: types2.TimeUnresolvable(types2.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     types2.NewTestMetadata(),
								AccessKeyId:  types2.String("AKIACKCEVSQ6C2EXAMPLE", types2.NewTestMetadata()),
								Active:       types2.Bool(true, types2.NewTestMetadata()),
								CreationDate: types2.Time(time.Now().Add(-time.Hour*24*120), types2.NewTestMetadata()),
								LastAccess:   types2.Time(time.Now().Add(-time.Hour*24*100), types2.NewTestMetadata()),
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
			results := CheckUnusedCredentialsDisabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUnusedCredentialsDisabled.Rule().LongID() {
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
