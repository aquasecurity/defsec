package test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/pkg/scanners/helm"
)

func Test_helm_scanner_with_archive(t *testing.T) {

	tests := []struct {
		testName    string
		chartName   string
		path        string
		archiveName string
	}{
		{
			testName:    "Parsing tarball 'mysql-8.8.26.tar'",
			chartName:   "mysql",
			path:        filepath.Join("testdata", "mysql-8.8.26.tar"),
			archiveName: "mysql-8.8.26.tar",
		},
	}

	for _, test := range tests {
		t.Logf("Running test: %s", test.testName)

		helmScanner := helm.New(options.ScannerWithEmbeddedPolicies(true))

		testTemp := t.TempDir()
		testFileName := filepath.Join(testTemp, test.archiveName)
		require.NoError(t, copyArchive(test.path, testFileName))

		testFs := os.DirFS(testTemp)
		results, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
		require.NoError(t, err)
		require.NotNil(t, results)

		failed := results.GetFailed()
		assert.Equal(t, 25, len(failed))

		visited := make(map[string]bool)
		var errorCodes []string
		for _, result := range failed {
			id := result.Flatten().RuleID
			if _, exists := visited[id]; !exists {
				visited[id] = true
				errorCodes = append(errorCodes, id)
			}
		}
		assert.Len(t, errorCodes, 19)

		sort.Strings(errorCodes)

		assert.Equal(t, []string{"AVD-KSV-0001", "AVD-KSV-0003", "AVD-KSV-0004",
			"AVD-KSV-0011", "AVD-KSV-0012", "AVD-KSV-0014",
			"AVD-KSV-0015", "AVD-KSV-0016", "AVD-KSV-0018",
			"AVD-KSV-0020", "AVD-KSV-0021", "AVD-KSV-0029",
			"AVD-KSV-0032", "AVD-KSV-0033", "AVD-KSV-0034",
			"AVD-KSV-0035", "AVD-KSV-0038", "AVD-KSV-0039",
			"AVD-KSV-0040"}, errorCodes)
	}
}

func Test_helm_scanner_with_dir(t *testing.T) {

	tests := []struct {
		testName  string
		chartName string
	}{
		{
			testName:  "Parsing directory testchart'",
			chartName: "testchart",
		},
	}

	for _, test := range tests {

		t.Logf("Running test: %s", test.testName)

		helmScanner := helm.New(options.ScannerWithEmbeddedPolicies(true))

		testFs := os.DirFS(filepath.Join("testdata", test.chartName))
		results, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
		require.NoError(t, err)
		require.NotNil(t, results)

		failed := results.GetFailed()
		assert.Equal(t, 20, len(failed))

		visited := make(map[string]bool)
		var errorCodes []string
		for _, result := range failed {
			id := result.Flatten().RuleID
			if _, exists := visited[id]; !exists {
				visited[id] = true
				errorCodes = append(errorCodes, id)
			}
		}

		sort.Strings(errorCodes)

		assert.Equal(t, []string{"AVD-KSV-0001", "AVD-KSV-0003", "AVD-KSV-0004",
			"AVD-KSV-0011", "AVD-KSV-0012", "AVD-KSV-0014",
			"AVD-KSV-0015", "AVD-KSV-0016", "AVD-KSV-0018",
			"AVD-KSV-0020", "AVD-KSV-0021", "AVD-KSV-0032",
			"AVD-KSV-0033", "AVD-KSV-0035", "AVD-KSV-0038",
			"AVD-KSV-0039", "AVD-KSV-0040"}, errorCodes)
	}
}

func copyArchive(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}
