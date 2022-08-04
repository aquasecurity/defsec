package iam

import (
	"testing"
	"time"

	"github.com/aquasecurity/defsec/internal/types"

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
						Metadata:   types.NewTestMetadata(),
						Name:       types.String("user", types.NewTestMetadata()),
						LastAccess: types.Time(time.Now(), types.NewTestMetadata()),
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
						Metadata:   types.NewTestMetadata(),
						Name:       types.String("user", types.NewTestMetadata()),
						LastAccess: types.TimeUnresolvable(types.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     types.NewTestMetadata(),
								AccessKeyId:  types.String("AKIACKCEVSQ6C2EXAMPLE", types.NewTestMetadata()),
								Active:       types.Bool(true, types.NewTestMetadata()),
								CreationDate: types.Time(time.Now().Add(-time.Hour*24*30), types.NewTestMetadata()),
								LastAccess:   types.Time(time.Now(), types.NewTestMetadata()),
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
						Metadata:   types.NewTestMetadata(),
						Name:       types.String("user", types.NewTestMetadata()),
						LastAccess: types.Time(time.Now().Add(-time.Hour*24*100), types.NewTestMetadata()),
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
						Metadata:   types.NewTestMetadata(),
						Name:       types.String("user", types.NewTestMetadata()),
						LastAccess: types.TimeUnresolvable(types.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     types.NewTestMetadata(),
								AccessKeyId:  types.String("AKIACKCEVSQ6C2EXAMPLE", types.NewTestMetadata()),
								Active:       types.Bool(false, types.NewTestMetadata()),
								CreationDate: types.Time(time.Now().Add(-time.Hour*24*120), types.NewTestMetadata()),
								LastAccess:   types.Time(time.Now().Add(-time.Hour*24*100), types.NewTestMetadata()),
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
						Metadata:   types.NewTestMetadata(),
						Name:       types.String("user", types.NewTestMetadata()),
						LastAccess: types.TimeUnresolvable(types.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     types.NewTestMetadata(),
								AccessKeyId:  types.String("AKIACKCEVSQ6C2EXAMPLE", types.NewTestMetadata()),
								Active:       types.Bool(true, types.NewTestMetadata()),
								CreationDate: types.Time(time.Now().Add(-time.Hour*24*120), types.NewTestMetadata()),
								LastAccess:   types.Time(time.Now().Add(-time.Hour*24*100), types.NewTestMetadata()),
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
