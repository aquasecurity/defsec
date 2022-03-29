package redshift

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUsesVPC(t *testing.T) {
	tests := []struct {
		name     string
		input    redshift.Redshift
		expected bool
	}{
		{
			name: "Redshift Cluster missing subnet name",
			input: redshift.Redshift{
				Metadata: types.NewTestMetadata(),
				Clusters: []redshift.Cluster{
					{
						Metadata:        types.NewTestMetadata(),
						SubnetGroupName: types.String("", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Redshift Cluster with subnet name",
			input: redshift.Redshift{
				Metadata: types.NewTestMetadata(),
				Clusters: []redshift.Cluster{
					{
						Metadata:        types.NewTestMetadata(),
						SubnetGroupName: types.String("redshift-subnet", types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Redshift = test.input
			results := CheckUsesVPC.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUsesVPC.Rule().LongID() {
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
