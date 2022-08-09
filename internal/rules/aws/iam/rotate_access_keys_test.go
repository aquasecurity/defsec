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

func TestCheckAccessKeysRotated(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Access key created a month ago",
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
			name: "Access key created 4 months ago",
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
								CreationDate: types2.Time(time.Now().Add(-time.Hour*24*30*4), types2.NewTestMetadata()),
								LastAccess:   types2.Time(time.Now(), types2.NewTestMetadata()),
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
			results := CheckAccessKeysRotated.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAccessKeysRotated.Rule().LongID() {
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
