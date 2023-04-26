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

		helmScanner := helm.New(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true))

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
		assert.Len(t, errorCodes, 12)

		sort.Strings(errorCodes)

		assert.Equal(t, []string{
			"AVD-KSV-0001", "AVD-KSV-0003",
			"AVD-KSV-0011", "AVD-KSV-0012", "AVD-KSV-0014",
			"AVD-KSV-0015", "AVD-KSV-0016", "AVD-KSV-0018",
			"AVD-KSV-0020", "AVD-KSV-0021", "AVD-KSV-0030",
			"AVD-KSV-0106",
		}, errorCodes)
	}
}

func Test_helm_scanner_with_missing_name_can_recover(t *testing.T) {

	tests := []struct {
		testName    string
		chartName   string
		path        string
		archiveName string
	}{
		{
			testName:    "Parsing tarball 'aws-cluster-autoscaler-bad.tar.gz'",
			chartName:   "aws-cluster-autoscaler",
			path:        filepath.Join("testdata", "aws-cluster-autoscaler-bad.tar.gz"),
			archiveName: "aws-cluster-autoscaler-bad.tar.gz",
		},
	}

	for _, test := range tests {
		t.Logf("Running test: %s", test.testName)

		helmScanner := helm.New(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true))

		testTemp := t.TempDir()
		testFileName := filepath.Join(testTemp, test.archiveName)
		require.NoError(t, copyArchive(test.path, testFileName))

		testFs := os.DirFS(testTemp)
		_, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
		require.NoError(t, err)
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

		helmScanner := helm.New(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true))

		testFs := os.DirFS(filepath.Join("testdata", test.chartName))
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

		sort.Strings(errorCodes)

		assert.Equal(t, []string{
			"AVD-KSV-0001", "AVD-KSV-0003",
			"AVD-KSV-0011", "AVD-KSV-0012", "AVD-KSV-0014",
			"AVD-KSV-0015", "AVD-KSV-0016", "AVD-KSV-0018",
			"AVD-KSV-0020", "AVD-KSV-0021", "AVD-KSV-0030",
			"AVD-KSV-0106",
		}, errorCodes)
	}
}

func Test_helm_scanner_with_custom_policies(t *testing.T) {
	regoRule := `
package user.kubernetes.ID001


__rego_metadata__ := {
    "id": "ID001",
	"avd_id": "AVD-USR-ID001",
    "title": "Services not allowed",
    "severity": "LOW",
    "description": "Services are not allowed because of some reasons.",
}

__rego_input__ := {
    "selector": [
        {"type": "kubernetes"},
    ],
}

deny[res] {
    input.kind == "Service"
    msg := sprintf("Found service '%s' but services are not allowed", [input.metadata.name])
    res := result.new(msg, input)
}
`
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
		t.Run(test.testName, func(t *testing.T) {
			t.Logf("Running test: %s", test.testName)

			helmScanner := helm.New(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true),
				options.ScannerWithPolicyDirs("rules"),
				options.ScannerWithPolicyNamespaces("user"))

			testTemp := t.TempDir()
			testFileName := filepath.Join(testTemp, test.archiveName)
			require.NoError(t, copyArchive(test.path, testFileName))

			policyDirName := filepath.Join(testTemp, "rules")
			require.NoError(t, os.Mkdir(policyDirName, 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(policyDirName, "rule.rego"), []byte(regoRule), 0o600))

			testFs := os.DirFS(testTemp)

			results, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
			require.NoError(t, err)
			require.NotNil(t, results)

			failed := results.GetFailed()
			assert.Equal(t, 14, len(failed))

			visited := make(map[string]bool)
			var errorCodes []string
			for _, result := range failed {
				id := result.Flatten().RuleID
				if _, exists := visited[id]; !exists {
					visited[id] = true
					errorCodes = append(errorCodes, id)
				}
			}
			assert.Len(t, errorCodes, 13)

			sort.Strings(errorCodes)

			assert.Equal(t, []string{
				"AVD-KSV-0001", "AVD-KSV-0003",
				"AVD-KSV-0011", "AVD-KSV-0012", "AVD-KSV-0014",
				"AVD-KSV-0015", "AVD-KSV-0016", "AVD-KSV-0018",
				"AVD-KSV-0020", "AVD-KSV-0021", "AVD-KSV-0030",
				"AVD-KSV-0106", "AVD-USR-ID001",
			}, errorCodes)
		})
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

func Test_helm_chart_with_templated_name(t *testing.T) {
	helmScanner := helm.New(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true))
	testFs := os.DirFS(filepath.Join("testdata", "templated-name"))
	_, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
	require.NoError(t, err)
}
