package terraformplan

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/terraformplan"
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
	require.Len(t, results, 13)
	require.Len(t, failedResults, 9)

	for _, r := range failedResults {
		fmt.Printf("%s\n", r.Flatten().LongID)
	}

}
