package test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aquasecurity/defsec/scanners/cloudformation/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_basic_cloudformation_scanning(t *testing.T) {
	cfScanner := scanner.New()

	err := cfScanner.AddPath("./examples/bucket.yaml")
	require.NoError(t, err)

	results, err := cfScanner.Scan()
	require.NoError(t, err)

	// check the number of expected results
	assert.Len(t, results, 7)
}

func Test_cloudformation_scanning_has_expected_errors(t *testing.T) {
	cfScanner := scanner.New()

	err := cfScanner.AddPath("./examples/bucket.yaml")
	require.NoError(t, err)

	results, err := cfScanner.Scan()
	require.NoError(t, err)

	// check the number of expected results
	assert.Len(t, results, 7)
	var errorCodes []string

	for _, result := range results {
		errorCodes = append(errorCodes, result.Flatten().RuleID)
	}
	assert.Len(t, errorCodes, 7)

	assert.Equal(t, []string{"AVD-AWS-0086", "AVD-AWS-0087", "AVD-AWS-0088", "AVD-AWS-0089", "AVD-AWS-0090", "AVD-AWS-0132", "AVD-AWS-0093"}, errorCodes)
}

func Test_cloudformation_scanning_with_debug(t *testing.T) {

	debugWriter := bytes.NewBufferString("")

	options := []scanner.Option{
		scanner.OptionWithDebug(debugWriter),
	}

	cfScanner := scanner.New(options...)

	err := cfScanner.AddPath("./examples/bucket.yaml")
	require.NoError(t, err)

	results, err := cfScanner.Scan()
	require.NoError(t, err)

	// check the number of expected results
	assert.Len(t, results, 7)

	// check debug is as expected
	assert.Greater(t, len(debugWriter.String()), 4096)
	assert.True(t, strings.HasPrefix(debugWriter.String(), "[debug:scan]"))

}

func Test_cloudformation_scanning_with_exclusions_has_expected_errors(t *testing.T) {

	options := []scanner.Option{
		scanner.OptionWithExcludedIDs([]string{"AVD-AWS-0087"}),
	}

	cfScanner := scanner.New(options...)

	err := cfScanner.AddPath("./examples/bucket.yaml")
	require.NoError(t, err)

	results, err := cfScanner.Scan()
	require.NoError(t, err)

	// check the number of expected results
	assert.Len(t, results, 6)
	var errorCodes []string

	for _, result := range results {
		errorCodes = append(errorCodes, result.Flatten().RuleID)
	}
	assert.Len(t, errorCodes, 6)

	assert.Equal(t, []string{"AVD-AWS-0086", "AVD-AWS-0088", "AVD-AWS-0089", "AVD-AWS-0090", "AVD-AWS-0132", "AVD-AWS-0093"}, errorCodes)
}

func Test_cloudformation_scanning_with_include_passed(t *testing.T) {
	options := []scanner.Option{
		scanner.OptionIncludePassed(),
	}

	cfScanner := scanner.New(options...)

	err := cfScanner.AddPath("./examples/bucket.yaml")
	require.NoError(t, err)

	results, err := cfScanner.Scan()
	require.NoError(t, err)

	// check the number of expected results
	assert.Len(t, results, 10)

}

func Test_cloudformation_scanning_with_ignores_has_expected_errors(t *testing.T) {

	cfScanner := scanner.New()

	err := cfScanner.AddPath("./examples/bucket_with_ignores.yaml")
	require.NoError(t, err)

	results, err := cfScanner.Scan()
	require.NoError(t, err)

	// check the number of expected results
	assert.Len(t, results, 6)
	var errorCodes []string

	for _, result := range results {
		errorCodes = append(errorCodes, result.Flatten().RuleID)
	}
	assert.Len(t, errorCodes, 6)

	assert.Equal(t, []string{"AVD-AWS-0086", "AVD-AWS-0088", "AVD-AWS-0089", "AVD-AWS-0090", "AVD-AWS-0132", "AVD-AWS-0093"}, errorCodes)
}
