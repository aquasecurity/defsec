package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/defsec/parsers/helm/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_helm_parser(t *testing.T) {

	tests := []struct {
		testName  string
		chartName string
	}{
		{
			testName:  "Parsing directory 'testchart'",
			chartName: "testchart",
		},
	}

	for _, test := range tests {
		chartName := test.chartName

		t.Logf("Running test: %s", test.testName)

		helmParser := parser.New(chartName)
		testFilePaths := getAllPaths(t, filepath.Join("testdata", chartName))

		helmParser.AddPaths(testFilePaths...)
		manifests, err := helmParser.RenderedChartFiles()
		require.NoError(t, err)

		assert.Len(t, manifests, 3)

		for _, manifest := range manifests {
			expectedPath := filepath.Join("testdata", "expected", manifest.TemplateFilePath)

			expectedContent, err := os.ReadFile(expectedPath)
			require.NoError(t, err)

			assert.Equal(t, string(expectedContent), manifest.ManifestContent)
		}
	}
}

func Test_helm_tarball_parser(t *testing.T) {

	tests := []struct {
		testName    string
		chartName   string
		archiveFile string
	}{
		{
			testName:    "standard tarball",
			chartName:   "mysql",
			archiveFile: "mysql-8.8.26.tar",
		},
		{
			testName:    "gzip tarball with tar.gz extension",
			chartName:   "mysql",
			archiveFile: "mysql-8.8.26.tar.gz",
		},
		{
			testName:    "gzip tarball with tgz extension",
			chartName:   "mysql",
			archiveFile: "mysql-8.8.26.tgz",
		},
	}

	for _, test := range tests {

		t.Logf("Running test: %s", test.testName)

		helmParser := parser.New(test.chartName)

		helmParser.AddPaths(filepath.Join("testdata", test.archiveFile))

		manifests, err := helmParser.RenderedChartFiles()
		require.NoError(t, err)

		assert.Len(t, manifests, 6)

		oneOf := []string{
			"configmap.yaml",
			"statefulset.yaml",
			"svc-headless.yaml",
			"svc.yaml",
			"secrets.yaml",
			"serviceaccount.yaml",
		}

		for _, manifest := range manifests {
			filename := filepath.Base(manifest.TemplateFilePath)
			assert.Contains(t, oneOf, filename)

			if strings.HasSuffix(manifest.TemplateFilePath, "secrets.yaml") {
				continue
			}
			expectedPath := filepath.Join("testdata", "expected", manifest.TemplateFilePath)

			expectedContent, err := os.ReadFile(expectedPath)
			require.NoError(t, err)

			assert.Equal(t, string(expectedContent), manifest.ManifestContent)
		}
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
