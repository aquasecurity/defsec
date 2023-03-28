package test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_basic_cloudformation_scanning(t *testing.T) {
	cfScanner := cloudformation.New()

	results, err := cfScanner.ScanFS(context.TODO(), os.DirFS("./examples/bucket"), ".")
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)
}

func Test_cloudformation_scanning_has_expected_errors(t *testing.T) {
	cfScanner := cloudformation.New()

	results, err := cfScanner.ScanFS(context.TODO(), os.DirFS("./examples/bucket"), ".")
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)
}

func Test_cloudformation_scanning_with_debug(t *testing.T) {

	debugWriter := bytes.NewBufferString("")

	scannerOptions := []options.ScannerOption{
		options.ScannerWithDebug(debugWriter),
	}
	cfScanner := cloudformation.New(scannerOptions...)

	_, err := cfScanner.ScanFS(context.TODO(), os.DirFS("./examples/bucket"), ".")
	require.NoError(t, err)

	// check debug is as expected
	assert.Greater(t, len(debugWriter.String()), 0)
}

func Test_basic_cloudformation_ignore(t *testing.T) {
	cfScanner := cloudformation.New()

	results, err := cfScanner.ScanFS(context.TODO(), os.DirFS("./examples/ignores"), "bucket_with_ignores.yaml")
	require.NoError(t, err)

	assert.Equal(t, len(results.GetIgnored()), 1)
}

func Test_basic_cloudformation_ignore_all(t *testing.T) {
	cfScanner := cloudformation.New()

	results, err := cfScanner.ScanFile(context.TODO(), os.DirFS("./examples/ignores"), "bucket_with_ignore_all.yaml")
	require.NoError(t, err)

	assert.Equal(t, len(results.GetFailed()), 0)
}
