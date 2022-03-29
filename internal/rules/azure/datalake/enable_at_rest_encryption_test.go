package datalake

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/datalake"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAtRestEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    datalake.DataLake
		expected bool
	}{
		{
			name: "unencrypted Data Lake store",
			input: datalake.DataLake{
				Metadata: types.NewTestMetadata(),
				Stores: []datalake.Store{
					{
						Metadata:         types.NewTestMetadata(),
						EnableEncryption: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "encrypted Data Lake store",
			input: datalake.DataLake{
				Metadata: types.NewTestMetadata(),
				Stores: []datalake.Store{
					{
						Metadata:         types.NewTestMetadata(),
						EnableEncryption: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.DataLake = test.input
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
