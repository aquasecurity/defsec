package test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aquasecurity/defsec/scanners/helm/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_helm_scanner_with_archive(t *testing.T) {

	tests := []struct {
		testName  string
		chartName string
		path      string
	}{
		{
			testName:  "Parsing tarball 'mysql-8.8.26.tar'",
			chartName: "mysql",
			path:      filepath.Join("testdata", "mysql-8.8.26.tar"),
		},
	}

	for _, test := range tests {
		t.Logf("Running test: %s", test.testName)

		helmScanner := scanner.New(test.chartName)
		err := helmScanner.AddPath(test.path)
		require.NoError(t, err)

		results, err := helmScanner.Scan()
		require.NoError(t, err)
		require.NotNil(t, results)

		failed := results.GetFailed()
		assert.Equal(t, 32, len(failed))

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

		files := getAllPaths(t, filepath.Join("testdata", test.chartName))

		t.Logf("Running test: %s", test.testName)

		helmScanner := scanner.New(test.chartName)
		for _, file := range files {
			err := helmScanner.AddPath(file)
			require.NoError(t, err)
		}

		results, err := helmScanner.Scan()
		require.NoError(t, err)
		require.NotNil(t, results)

		failed := results.GetFailed()
		assert.Equal(t, 22, len(failed))

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

func getAllPaths(t *testing.T, rootPath string) (paths []string) {
	err := filepath.WalkDir(rootPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	require.NoError(t, err)
	return paths
}
