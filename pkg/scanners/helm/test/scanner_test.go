package test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

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

		helmScanner := helm.New(test.chartName)

		testTemp := t.TempDir()
		testFileName := filepath.Join(testTemp, test.archiveName)
		require.NoError(t, copyArchive(test.path, testFileName))

		testFs := os.DirFS(testTemp)
		results, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
		require.NoError(t, err)
		require.NotNil(t, results)

		failed := results.GetFailed()
		assert.Equal(t, 12, len(failed))

		visited := make(map[string]bool)
		var errorCodes []string
		for _, result := range failed {
			id := result.Flatten().RuleID
			if _, exists := visited[id]; !exists {
				visited[id] = true
				errorCodes = append(errorCodes, id)
			}
		}
		assert.Len(t, errorCodes, 2)

		sort.Strings(errorCodes)

		assert.Equal(t, []string{"AVD-KSV-0039",
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

		helmScanner := helm.New(test.chartName)

		testFs := os.DirFS(filepath.Join("testdata", test.chartName))
		results, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
		require.NoError(t, err)
		require.NotNil(t, results)

		failed := results.GetFailed()
		assert.Equal(t, 6, len(failed))

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

		assert.Equal(t, []string{"AVD-KSV-0039", "AVD-KSV-0040"}, errorCodes)
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
