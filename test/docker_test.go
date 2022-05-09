package test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/dockerfile"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Docker_RegoPoliciesFromDisk(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("./testdata/dockerfile")
	require.NoError(t, err)

	scanner := dockerfile.NewScanner(
		options.ScannerWithPolicyDirs("internal/rules"),
	)

	srcFS := os.DirFS("../")

	results, err := scanner.ScanFS(context.TODO(), srcFS, "test/testdata/dockerfile")
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			require.NoError(t, err)
			t.Run(entry.Name(), func(t *testing.T) {
				var matched int
				for _, result := range results {
					if (result.Rule().AVDID == entry.Name() || result.Rule().LegacyID == entry.Name()) && result.Status() == scan.StatusFailed {
						if result.Description() != "Specify at least 1 USER command in Dockerfile with non-root user as argument" {
							assert.Greater(t, result.Range().GetStartLine(), 0)
							assert.Greater(t, result.Range().GetEndLine(), 0)
						}
						assert.Equal(t, fmt.Sprintf("test/testdata/dockerfile/%s/Dockerfile.denied", entry.Name()), result.Range().GetFilename())
						matched++
					}
				}
				assert.Equal(t, 1, matched, "Rule should be matched once")
			})

		})
	}
}

func Test_Docker_RegoPoliciesEmbedded(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("./testdata/dockerfile")
	require.NoError(t, err)

	scanner := dockerfile.NewScanner(options.ScannerWithEmbeddedPolicies(true))
	srcFS := os.DirFS("../")

	results, err := scanner.ScanFS(context.TODO(), srcFS, "test/testdata/dockerfile")
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			require.NoError(t, err)
			t.Run(entry.Name(), func(t *testing.T) {
				var matched bool
				for _, result := range results {
					if (result.Rule().AVDID == entry.Name() || result.Rule().LegacyID == entry.Name()) && result.Status() == scan.StatusFailed {
						if result.Description() != "Specify at least 1 USER command in Dockerfile with non-root user as argument" {
							assert.Greater(t, result.Range().GetStartLine(), 0)
							assert.Greater(t, result.Range().GetEndLine(), 0)
						}
						assert.Equal(t, fmt.Sprintf("test/testdata/dockerfile/%s/Dockerfile.denied", entry.Name()), result.Range().GetFilename())
						matched = true
					}
				}
				assert.True(t, matched)
			})

		})
	}
}
