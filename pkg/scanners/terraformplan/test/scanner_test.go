package terraformplan

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/terraformplan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Scanning_Plan(t *testing.T) {
	scanner := terraformplan.New()
	b, _ := os.ReadFile("testdata/plan.json")
	testFS := fstest.MapFS{
		"testdata/plan.json": {Data: b},
	}

	results, err := scanner.ScanFile("testdata/plan.json", testFS)
	require.NoError(t, err)
	require.NotNil(t, results)

	var failedResults scan.Results
	for _, r := range results {
		if r.Status() == scan.StatusFailed {
			failedResults = append(failedResults, r)
		}
	}
	assert.Len(t, results, 13)
	assert.Len(t, failedResults, 9)

}
