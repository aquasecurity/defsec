package test

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/defsec/rules"

	"github.com/aquasecurity/defsec/scanners/dockerfile"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Docker_RegoPoliciesFromDisk(t *testing.T) {
	require.NoError(t, filepath.Walk("./testdata", func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		id := filepath.Base(filepath.Dir(path))
		positiveExpected := strings.HasSuffix(path, ".denied")
		testName := "negative"
		if positiveExpected {
			testName = "positive"
		}

		t.Run(fmt.Sprintf("%s:%s", id, testName), func(t *testing.T) {

			debugLog := bytes.NewBuffer([]byte{})

			scanner := dockerfile.NewScanner(
				dockerfile.OptionWithPolicyDirs("../rules/"),
				dockerfile.OptionWithDebug(debugLog),
			)
			require.NoError(t, scanner.AddPath(path))

			results, err := scanner.Scan(context.TODO())
			require.NoError(t, err)

			absPath, err := filepath.Abs(path)
			if err != nil {
				require.NoError(t, err)
			}

			var matched bool
			for _, result := range results {
				if (result.Rule().AVDID == id || result.Rule().LegacyID == id) && result.Status() == rules.StatusFailed {
					if result.Description() != "Specify at least 1 USER command in Dockerfile with non-root user as argument" {
						assert.Greater(t, result.Range().GetStartLine(), 0)
						assert.Greater(t, result.Range().GetEndLine(), 0)
					}
					assert.Equal(t, absPath, result.Range().GetFilename())
					matched = true
					break
				}
			}

			assert.Equal(t, positiveExpected, matched)

			if t.Failed() {
				fmt.Printf("Debug logs:\n%s\n", debugLog.String())
			}
		})
		return nil
	}))
}

func Test_Docker_RegoPoliciesEmbedded(t *testing.T) {
	require.NoError(t, filepath.Walk("./testdata", func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		id := filepath.Base(filepath.Dir(path))
		positiveExpected := strings.HasSuffix(path, ".denied")
		testName := "negative"
		if positiveExpected {
			testName = "positive"
		}

		t.Run(fmt.Sprintf("%s:%s", id, testName), func(t *testing.T) {

			debugLog := bytes.NewBuffer([]byte{})

			scanner := dockerfile.NewScanner(
				dockerfile.OptionWithDebug(debugLog),
			)
			require.NoError(t, scanner.AddPath(path))

			results, err := scanner.Scan(context.TODO())
			require.NoError(t, err)

			var matched bool
			for _, result := range results {
				if (result.Rule().AVDID == id || result.Rule().LegacyID == id) && result.Status() == rules.StatusFailed {
					matched = true
					break
				}
			}

			assert.Equal(t, positiveExpected, matched)

			if t.Failed() {
				fmt.Printf("Debug logs:\n%s\n", debugLog.String())
			}
		})
		return nil
	}))
}
