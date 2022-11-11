package terraformplan

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/terraformplan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Scanning_Plan(t *testing.T) {
	scanner := terraformplan.New()
	results, err := scanner.ScanFile("testdata/plan.json")
	require.NoError(t, err)
	require.NotNil(t, results)

	var failedResults scan.Results
	for _, r := range results {
		if r.Status() == scan.StatusFailed {
			failedResults = append(failedResults, r)
		}
	}
	assert.Len(t, results, 14)
	assert.Len(t, failedResults, 10)

}
