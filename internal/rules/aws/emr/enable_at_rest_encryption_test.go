package emr

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/emr"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

// TODO Update this test to check for the rule
// func TestCheckEnableAtRestEncryption(t *testing.T) {
// 	t.SkipNow()
// 	tests := []struct {
// 		name     string
// 		input    autoscaling.Autoscaling
// 		expected bool
// 	}{
// 		{
// 			name:     "positive result",
// 			input:    autoscaling.Autoscaling{},
// 			expected: true,
// 		},
// 		{
// 			name:     "negative result",
// 			input:    autoscaling.Autoscaling{},
// 			expected: false,
// 		},
// 	}
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			var testState state.State
// 			testState.AWS.Autoscaling = test.input
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

func TestCheckEnableInTransitEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    emr.EMR
		expected bool
	}{
		{
			name: "EMR cluster with in-transit encryption disabled",
			input: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Metadata:                  types.NewTestMetadata(),
						EnableInTransitEncryption: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Emr cluster with in-transit encryption enabled",
			input: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Metadata:                  types.NewTestMetadata(),
						EnableInTransitEncryption: types.Bool(true, types.NewTestMetadata()),
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
