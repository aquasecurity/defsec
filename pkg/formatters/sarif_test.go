package formatters

import (
	"bytes"
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SARIF(t *testing.T) {
	want := `{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "informationUri": "https://github.com/aquasecurity/defsec",
          "name": "defsec",
          "rules": [
            {
              "id": "aws-dynamodb-enable-at-rest-encryption",
              "shortDescription": {
                "text": "summary"
              },
              "helpUri": "https://google.com"
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "aws-dynamodb-enable-at-rest-encryption",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "Cluster encryption is not enabled."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "test.test"
                },
                "region": {
                  "startLine": 123,
                  "endLine": 123
                }
              }
            }
          ]
        }
      ]
    }
  ]
}`
	buffer := bytes.NewBuffer([]byte{})
	formatter := New().AsSARIF().WithWriter(buffer).Build()
	var results scan.Results
	results.Add("Cluster encryption is not enabled.",
		dynamodb.ServerSideEncryption{
			Metadata: defsecTypes.NewTestMetadata(),
			Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
		})
	results.SetRule(scan.Rule{
		AVDID:       "AVD-AA-9999",
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

func Test_SARIF_nested_paths(t *testing.T) {
	want := `{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "informationUri": "https://github.com/aquasecurity/defsec",
          "name": "defsec",
          "rules": [
            {
              "id": "aws-ec2-add-description-to-security-group-rule",
              "shortDescription": {
                "text": "summary"
              },
              "helpUri": "link"
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "aws-ec2-add-description-to-security-group-rule",
          "ruleIndex": 0,
          "level": "note",
          "message": {
            "text": "Security group rule does not have a description."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "test.test"
                },
                "region": {
                  "startLine": 123,
                  "endLine": 123
                }
              }
            }
          ]
        }
      ]
    }
  ]
}`
	buffer := bytes.NewBuffer([]byte{})
	formatter := New().AsSARIF().WithWriter(buffer).Build()
	var results scan.Results

	parentMetadata := defsecTypes.NewTestMetadata()
	parentMetadata.SetRange(defsecTypes.NewRange("main.tf", 1, 2, "", nil))

	nestedMetadata := defsecTypes.NewTestMetadata().WithParent(parentMetadata)

	results.Add("Security group rule does not have a description.",
		ec2.SecurityGroup{
			Metadata: nestedMetadata,
		},
	)
	results.SetRule(scan.Rule{
		AVDID:       "AVD-AWS-0124",
		ShortCode:   "add-description-to-security-group-rule",
		Summary:     "summary",
		Explanation: "explanation",
		Impact:      "impact",
		Resolution:  "resolution",
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		Links: []string{
			"link",
		},
		Severity: severity.Low,
	})
	require.NoError(t, formatter.Output(results))
	assert.Equal(t, want, buffer.String())
}
