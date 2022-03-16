package formatters

import (
	"bytes"
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/severity"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/rules"
)

func Test_CSV(t *testing.T) {
	want := `file,start_line,end_line,rule_id,severity,description,link,passed
test.test,123,123,aws-dynamodb-enable-at-rest-encryption,HIGH,Cluster encryption is not enabled.,,false
`
	buffer := bytes.NewBuffer([]byte{})
	formatter := New().AsCSV().WithWriter(buffer).Build()
	var results rules.Results
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: types.NewTestMetadata(),
			Enabled:  types.Bool(false, types.NewTestMetadata()),
		})
	results.SetRule(rules.Rule{Severity: severity.High, Provider: providers.AWSProvider, Service: "dynamodb", ShortCode: "enable-at-rest-encryption"})
	require.NoError(t, formatter.Output(results))
	assert.Equal(t, want, buffer.String())
}

func Test_CSV_WithoutPassed(t *testing.T) {
	want := `file,start_line,end_line,rule_id,severity,description,link,passed
test.test,123,123,aws-dynamodb-enable-at-rest-encryption,HIGH,Cluster encryption is not enabled.,,false
`
	buffer := bytes.NewBuffer([]byte{})
	formatter := New().AsCSV().WithWriter(buffer).Build()
	var results rules.Results
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: types.NewTestMetadata(),
			Enabled:  types.Bool(false, types.NewTestMetadata()),
		})
	results.AddPassed(types.NewTestMetadata(), "Everything is fine.")
	results.SetRule(rules.Rule{Severity: severity.High, Provider: providers.AWSProvider, Service: "dynamodb", ShortCode: "enable-at-rest-encryption"})
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
	var results rules.Results
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: types.NewTestMetadata(),
			Enabled:  types.Bool(false, types.NewTestMetadata()),
		})
	results.AddPassed(types.NewTestMetadata(), "Everything is fine.")
	results.SetRule(rules.Rule{Severity: severity.High, Provider: providers.AWSProvider, Service: "dynamodb", ShortCode: "enable-at-rest-encryption"})
	require.NoError(t, formatter.Output(results))
	assert.Equal(t, want, buffer.String())
}
