package formatters

import (
	"bytes"
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_CSV(t *testing.T) {
	want := `file,start_line,end_line,rule_id,severity,description,link,passed
test.test,123,123,aws-dynamodb-enable-at-rest-encryption,HIGH,Cluster encryption is not enabled.,,false
`
	buffer := bytes.NewBuffer([]byte{})
	formatter := New().AsCSV().WithWriter(buffer).Build()
	var results scan.Results
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: defsecTypes.NewTestMetadata(),
			Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
		})
	results.SetRule(scan.Rule{Severity: severity.High, Provider: providers.AWSProvider, Service: "dynamodb", ShortCode: "enable-at-rest-encryption"})
	require.NoError(t, formatter.Output(results))
	assert.Equal(t, want, buffer.String())
}

func Test_CSV_WithoutPassed(t *testing.T) {
	want := `file,start_line,end_line,rule_id,severity,description,link,passed
test.test,123,123,aws-dynamodb-enable-at-rest-encryption,HIGH,Cluster encryption is not enabled.,,false
`
	buffer := bytes.NewBuffer([]byte{})
	formatter := New().AsCSV().WithWriter(buffer).Build()
	var results scan.Results
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: defsecTypes.NewTestMetadata(),
			Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
		})
	results.AddPassed(defsecTypes.NewTestMetadata(), "Everything is fine.")
	results.SetRule(scan.Rule{Severity: severity.High, Provider: providers.AWSProvider, Service: "dynamodb", ShortCode: "enable-at-rest-encryption"})
	require.NoError(t, formatter.Output(results))
	assert.Equal(t, want, buffer.String())
}

func Test_CSV_WithPassed(t *testing.T) {
	want := `file,start_line,end_line,rule_id,severity,description,link,passed
test.test,123,123,aws-dynamodb-enable-at-rest-encryption,HIGH,Cluster encryption is not enabled.,,false
test.test,123,123,aws-dynamodb-enable-at-rest-encryption,HIGH,Everything is fine.,,true
`
	buffer := bytes.NewBuffer([]byte{})
	formatter := New().AsCSV().WithWriter(buffer).WithIncludePassed(true).Build()
	var results scan.Results
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: defsecTypes.NewTestMetadata(),
			Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
		})
	results.AddPassed(defsecTypes.NewTestMetadata(), "Everything is fine.")
	results.SetRule(scan.Rule{Severity: severity.High, Provider: providers.AWSProvider, Service: "dynamodb", ShortCode: "enable-at-rest-encryption"})
	require.NoError(t, formatter.Output(results))
	assert.Equal(t, want, buffer.String())
}
