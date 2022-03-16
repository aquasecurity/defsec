package test

import (
	"bytes"
	"context"
	"testing"

	"github.com/aquasecurity/defsec/scanners/cloudformation/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_basic_cloudformation_scanning(t *testing.T) {
	cfScanner := scanner.New()

	err := cfScanner.AddPath("./examples/bucket.yaml")
	require.NoError(t, err)

	results, err := cfScanner.Scan(context.TODO())
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)
}

func Test_cloudformation_scanning_has_expected_errors(t *testing.T) {
	cfScanner := scanner.New()

	err := cfScanner.AddPath("./examples/bucket.yaml")
	require.NoError(t, err)

	results, err := cfScanner.Scan(context.TODO())
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)
}

func Test_cloudformation_scanning_with_debug(t *testing.T) {

	debugWriter := bytes.NewBufferString("")

	options := []scanner.Option{
		scanner.OptionWithDebug(debugWriter),
	}

	cfScanner := scanner.New(options...)

	err := cfScanner.AddPath("./examples/bucket.yaml")
	require.NoError(t, err)

	_, err = cfScanner.Scan(context.TODO())
	require.NoError(t, err)

	// check debug is as expected
	assert.Greater(t, len(debugWriter.String()), 0)
}

func Test_cloudformation_scanning_with_exclusions_has_expected_errors(t *testing.T) {

	options := []scanner.Option{
		scanner.OptionWithExcludedIDs([]string{"AVD-AWS-0087"}),
	}

	cfScanner := scanner.New(options...)

	err := cfScanner.AddPath("./examples/bucket.yaml")
	require.NoError(t, err)

	results, err := cfScanner.Scan(context.TODO())
	require.NoError(t, err)

	// check the number of expected results
	assert.Greater(t, len(results.GetFailed()), 0)
	assert.Greater(t, len(results.GetIgnored()), 0)
}

func Test_cloudformation_scanning_with_include_passed(t *testing.T) {
	options := []scanner.Option{
		scanner.OptionIncludePassed(),
	}

	cfScanner := scanner.New(options...)

	err := cfScanner.AddPath("./examples/bucket.yaml")
	require.NoError(t, err)

	results, err := cfScanner.Scan(context.TODO())
	require.NoError(t, err)

	// check the number of expected results
	assert.Greater(t, len(results.GetPassed()), 0)

}

func Test_cloudformation_scanning_with_ignores_has_expected_errors(t *testing.T) {

	cfScanner := scanner.New()

	err := cfScanner.AddPath("./examples/bucket_with_ignores.yaml")
	require.NoError(t, err)

	results, err := cfScanner.Scan(context.TODO())
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)
	assert.Greater(t, len(results.GetIgnored()), 0)
}
