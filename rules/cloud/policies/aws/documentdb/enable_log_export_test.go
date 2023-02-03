package documentdb

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/documentdb"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableLogExport(t *testing.T) {
	tests := []struct {
		name     string
		input    documentdb.DocumentDB
		expected bool
	}{
		{
			name: "DocDB Cluster not exporting logs",
			input: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EnabledLogExports: []defsecTypes.StringValue{
							defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "DocDB Cluster exporting audit logs",
			input: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EnabledLogExports: []defsecTypes.StringValue{
							defsecTypes.String(documentdb.LogExportAudit, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "DocDB Cluster exporting profiler logs",
			input: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						EnabledLogExports: []defsecTypes.StringValue{
							defsecTypes.String(documentdb.LogExportProfiler, defsecTypes.NewTestMetadata()),
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
			testState.AWS.DocumentDB = test.input
			results := CheckEnableLogExport.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableLogExport.Rule().LongID() {
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
