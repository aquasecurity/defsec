package test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/defsec/parsers/helm/parser"
	kparser "github.com/aquasecurity/defsec/parsers/kubernetes/parser"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func Test_unpack_object(t *testing.T) {

	p := parser.New("testchart")
	testFilePaths := getAllPaths(t, filepath.Join("testdata", "testchart"))
	p.AddPaths(testFilePaths...)

	charts, err := p.RenderedChartFiles()
	require.NoError(t, err)

	for _, chart := range charts {
		var manifest kparser.Manifest
		err := yaml.Unmarshal([]byte(chart.ManifestContent), &manifest)
		require.NoError(t, err)
		require.NotNil(t, manifest)
		require.NotNil(t, manifest.Content)
		require.NotNil(t, manifest.ToRegoMap())

		content, err := json.MarshalIndent(manifest, "", " ")
		require.NoError(t, err)
		t.Log(string(content))
	}
}

func Test_unpack_archived_object(t *testing.T) {

	p := parser.New("mysql")
	p.AddPaths(filepath.Join("testdata", "mysql-8.8.26.tgz"))

	charts, err := p.RenderedChartFiles()
	require.NoError(t, err)

	for _, chart := range charts {
		var manifest kparser.Manifest
		err := yaml.Unmarshal([]byte(chart.ManifestContent), &manifest)
		require.NoError(t, err)
		require.NotNil(t, manifest)
		require.NotNil(t, manifest.Content)
		require.NotNil(t, manifest.ToRegoMap())
	}

}
