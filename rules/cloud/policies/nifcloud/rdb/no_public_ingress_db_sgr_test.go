package rdb

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/rdb"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngressDBSgr(t *testing.T) {
	tests := []struct {
		name     string
		input    rdb.RDB
		expected bool
	}{
		{
			name: "NIFCLOUD ingress db security group rule with wildcard address",
			input: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						CIDRs: []defsecTypes.StringValue{
							defsecTypes.String("0.0.0.0/0", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD ingress db security group rule with private address",
			input: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						CIDRs: []defsecTypes.StringValue{
							defsecTypes.String("10.0.0.0/16", defsecTypes.NewTestMetadata()),
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
			testState.Nifcloud.RDB = test.input
			results := CheckNoPublicIngressDBSgr.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngressDBSgr.Rule().LongID() {
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
