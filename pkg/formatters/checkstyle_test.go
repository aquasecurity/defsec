package formatters

import (
	"bytes"
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"

	"github.com/stretchr/testify/assert"
)

func TestOutputCheckStyle(t *testing.T) {
	want := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<checkstyle version=\"5.0\">\n\t<file name=\"test.test\">\n\t\t<error source=\"aws-dynamodb-enable-at-rest-encryption\" line=\"123\" column=\"0\" severity=\"error\" message=\"Cluster encryption is not enabled.\" link=\"\"></error>\n\t</file>\n</checkstyle>"
	wantErr := error(nil)

	results := scan.Results{}
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: types2.NewTestMetadata(),
			Enabled:  types2.Bool(false, types2.NewTestMetadata()),
		})
	results.SetRule(scan.Rule{Severity: severity.High, Provider: providers.AWSProvider, Service: "dynamodb", ShortCode: "enable-at-rest-encryption"})

	var buf bytes.Buffer
	factory := New().AsCheckStyle().WithWriter(&buf).Build()

	err := factory.Output(results)

	assert.Equal(t, wantErr, err)
	assert.Equal(t, want, buf.String())

}

func TestConvertSeverity(t *testing.T) {
	type test struct {
		severity severity.Severity
		want     string
	}

	tests := []test{
		{severity: severity.Low, want: "info"},
		{severity: severity.Medium, want: "warning"},
		{severity: severity.High, want: "error"},
		{severity: severity.Critical, want: "error"},
		{severity: severity.None, want: "error"},
	}

	for _, tc := range tests {
		got := convertSeverity(tc.severity)
		assert.Equal(t, tc.want, got)
	}
}
