package formatters

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_JUnit(t *testing.T) {
	want := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="%s" failures="1" tests="1">
	<testcase classname="test.test" name="[aws-dynamodb-enable-at-rest-encryption][HIGH] - Cluster encryption is not enabled." time="0">
		<failure message="Cluster encryption is not enabled." type="">test.test:123&#xA;&#xA;&#xA;&#xA;See https://google.com</failure>
	</testcase>
</testsuite>`, filepath.Base(os.Args[0]))
	buffer := bytes.NewBuffer([]byte{})
	formatter := New().AsJUnit().WithWriter(buffer).Build()
	var results scan.Results
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: types.NewTestMetadata(),
			Enabled:  types.Bool(false, types.NewTestMetadata()),
		})
	results.SetRule(scan.Rule{
		AVDID:       "AVD-AA-9999",
		LegacyID:    "AAA999",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "summary",
		Explanation: "explanation",
		Impact:      "impact",
		Resolution:  "resolution",
		Provider:    providers.AWSProvider,
		Service:     "dynamodb",
		Links: []string{
			"https://google.com",
		},
		Severity: severity.High,
	})
	require.NoError(t, formatter.Output(results))
	assert.Equal(t, want, buffer.String())
}
