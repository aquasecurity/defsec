package test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/dockerfile"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Docker_RegoPoliciesFromDisk(t *testing.T) {

	entries, err := os.ReadDir("./testdata")
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join("testdata", entry.Name())
			files, err := os.ReadDir(dir)
			require.NoError(t, err)
			for _, file := range files {
				if file.IsDir() {
					continue
				}
				t.Run(file.Name(), func(t *testing.T) {
					expectPositive := strings.HasSuffix(file.Name(), ".denied")
					scanner := dockerfile.NewScanner(
						dockerfile.OptionWithPolicyDirs("../internal/rules/"),
					)
					fs := os.DirFS(dir)
					results, err := scanner.ScanFile(context.TODO(), fs, file.Name())
					require.NoError(t, err)
					var matched bool
					for _, result := range results {
						if (result.Rule().AVDID == entry.Name() || result.Rule().LegacyID == entry.Name()) && result.Status() == scan.StatusFailed {
							if result.Description() != "Specify at least 1 USER command in Dockerfile with non-root user as argument" {
								assert.Greater(t, result.Range().GetStartLine(), 0)
								assert.Greater(t, result.Range().GetEndLine(), 0)
							}
							assert.Equal(t, file.Name(), result.Range().GetFilename())
							matched = true
							break
						}
					}

					assert.Equal(t, expectPositive, matched)
				})
			}

		})
	}
}

func Test_Docker_RegoPoliciesEmbedded(t *testing.T) {

	entries, err := os.ReadDir("./testdata")
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join("testdata", entry.Name())
			files, err := os.ReadDir(filepath.Join("testdata", entry.Name()))
			require.NoError(t, err)
			for _, file := range files {
				if file.IsDir() {
					continue
				}
				t.Run(file.Name(), func(t *testing.T) {
					expectPositive := strings.HasSuffix(file.Name(), ".denied")
					scanner := dockerfile.NewScanner()
					fs := os.DirFS(dir)
					results, err := scanner.ScanFile(context.TODO(), fs, file.Name())
					require.NoError(t, err)
					var matched bool
					for _, result := range results {
						if (result.Rule().AVDID == entry.Name() || result.Rule().LegacyID == entry.Name()) && result.Status() == scan.StatusFailed {
							if result.Description() != "Specify at least 1 USER command in Dockerfile with non-root user as argument" {
								assert.Greater(t, result.Range().GetStartLine(), 0)
								assert.Greater(t, result.Range().GetEndLine(), 0)
							}
							assert.Equal(t, file.Name(), result.Range().GetFilename())
							matched = true
							break
						}
					}

					assert.Equal(t, expectPositive, matched)
				})
			}

		})
	}
}
