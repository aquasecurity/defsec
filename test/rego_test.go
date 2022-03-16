package test

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/defsec/test/testutil/filesystem"

	"github.com/aquasecurity/defsec/scanners/terraform"

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

func Test_Defsec_RegoPoliciesFromDisk(t *testing.T) {

	fs, err := filesystem.New()
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()

	err = fs.WriteFile("/code/main.tf", []byte(`
resource "aws_s3_bucket" "my-bucket" {
	bucket = "evil"
}
`))
	require.NoError(t, err)

	err = fs.WriteFile("/rules/test.rego", []byte(`
package appshield.abcdefg

__rego_metadata__ := {
	"id": "TEST123",
	"avd_id": "AVD-TEST-0123",
	"title": "Buckets should not be evil",
	"short_code": "no-evil-buckets",
	"severity": "CRITICAL",
	"type": "DefSec Security Check",
	"description": "You should not allow buckets to be evil",
	"recommended_actions": "Use a good bucket instead",
	"url": "https://google.com/search?q=is+my+bucket+evil",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "defsec"}],
}

deny[res] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "evil"
	res := {
    	"msg": "do not use evil buckets",
    	"filepath": bucket.name.filepath,
    	"startline": bucket.name.startline,
        "endline": bucket.name.endline,
    }
}

`))
	require.NoError(t, err)

	debugLog := bytes.NewBuffer([]byte{})
	scanner := terraform.New(
		terraform.OptionWithDebugWriter(debugLog),
		terraform.OptionWithPolicyDirs([]string{fs.RealPath("rules")}),
	)
	if err := scanner.AddPath(fs.RealPath("/code/main.tf")); err != nil {
		t.Error(err)
	}

	results, _, err := scanner.Scan()
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 1)

	var found bool
	for _, result := range results.GetFailed() {
		if result.Rule().AVDID == "AVD-TEST-0123" {
			found = true
			break
		}
	}
	assert.True(t, found)

	if t.Failed() {
		fmt.Printf("Debug logs:\n%s\n", debugLog.String())
	}

}
