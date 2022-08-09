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

func TestCheckLimitRootAccountUsage(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "root user, never logged in",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("root", types2.NewTestMetadata()),
						LastAccess: types2.TimeUnresolvable(types2.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "root user, logged in months ago",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("other", types2.NewTestMetadata()),
						LastAccess: types2.Time(time.Now().Add(-time.Hour*24*90), types2.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "root user, logged in today",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("root", types2.NewTestMetadata()),
						LastAccess: types2.Time(time.Now().Add(-time.Hour), types2.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "other user, logged in today",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("other", types2.NewTestMetadata()),
						LastAccess: types2.Time(time.Now().Add(-time.Hour), types2.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := checkLimitRootAccountUsage.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkLimitRootAccountUsage.Rule().LongID() {
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
