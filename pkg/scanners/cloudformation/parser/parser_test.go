package parser

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseFile(t *testing.T, source string, name string) (FileContexts, error) {
	tmp, err := os.MkdirTemp(os.TempDir(), "defsec")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmp) }()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, name), []byte(source), 0600))
	fs := os.DirFS(tmp)
	return New().ParseFS(context.TODO(), fs, ".")
}

func Test_parse_yaml(t *testing.T) {

	source := `---
Parameters:
  BucketName: 
    Type: String
    Default: naughty
  EncryptBucket:
    Type: Boolean
    Default: false
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: naughty
      BucketEncryption:
        ServerSideEncryptionConfiguration:
        - BucketKeyEnabled: 
            Ref: EncryptBucket`

	files, err := parseFile(t, source, "cf.yaml")
	require.NoError(t, err)
	assert.Len(t, files, 1)
	file := files[0]

	assert.Len(t, file.Resources, 1)
	assert.Len(t, file.Parameters, 2)

	bucket, ok := file.Resources["S3Bucket"]
	require.True(t, ok, "S3Bucket resource should be available")
	assert.Equal(t, "cf.yaml", bucket.Range().GetFilename())
	assert.Equal(t, 10, bucket.Range().GetStartLine())
	assert.Equal(t, 17, bucket.Range().GetEndLine())
}

func Test_parse_json(t *testing.T) {
	source := `{
  "Parameters": {
    "BucketName": {
      "Type": "String",
      "Default": "naughty"
    },
    "BucketKeyEnabled": {
      "Type": "Boolean",
      "Default": false
    }
  },
  "Resources": {
    "S3Bucket": {
      "Type": "AWS::S3::Bucket",
      "properties": {
        "BucketName": {
          "Ref": "BucketName"
        },
        "BucketEncryption": {
          "ServerSideEncryptionConfiguration": [
            {
              "BucketKeyEnabled": {
                  "Ref": "BucketKeyEnabled"
              }
            }
          ]
        }
      }
    }
  }
}
`

	files, err := parseFile(t, source, "cf.json")
	require.NoError(t, err)
	assert.Len(t, files, 1)
	file := files[0]

	assert.Len(t, file.Resources, 1)
	assert.Len(t, file.Parameters, 2)
}

func Test_parse_yaml_with_map_ref(t *testing.T) {

	source := `---
Parameters:
  BucketName: 
    Type: String
    Default: referencedBucket
  EncryptBucket:
    Type: Boolean
    Default: false
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName:
        Ref: BucketName
      BucketEncryption:
        ServerSideEncryptionConfiguration:
        - BucketKeyEnabled: 
            Ref: EncryptBucket`

	files, err := parseFile(t, source, "cf.yaml")
	require.NoError(t, err)
	assert.Len(t, files, 1)
	file := files[0]

	assert.Len(t, file.Resources, 1)
	assert.Len(t, file.Parameters, 2)

	res := file.GetResourceByLogicalID("S3Bucket")
	assert.NotNil(t, res)

	refProp := res.GetProperty("BucketName")
	assert.False(t, refProp.IsNil())
	assert.Equal(t, "referencedBucket", refProp.AsString())
}

func Test_parse_yaml_with_intrinsic_functions(t *testing.T) {

	source := `---
Parameters:
  BucketName: 
    Type: String
    Default: somebucket
  EncryptBucket:
    Type: Boolean
    Default: false
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: !Ref BucketName
      BucketEncryption:
        ServerSideEncryptionConfiguration:
        - BucketKeyEnabled: false
`

	files, err := parseFile(t, source, "cf.yaml")
	require.NoError(t, err)
	assert.Len(t, files, 1)
	ctx := files[0]

	assert.Len(t, ctx.Resources, 1)
	assert.Len(t, ctx.Parameters, 2)

	res := ctx.GetResourceByLogicalID("S3Bucket")
	assert.NotNil(t, res)

	refProp := res.GetProperty("BucketName")
	assert.False(t, refProp.IsNil())
	assert.Equal(t, "somebucket", refProp.AsString())
}

func createTestFileContext(t *testing.T, source string) *FileContext {
	contexts, err := parseFile(t, source, "main.yaml")
	require.NoError(t, err)
	require.Len(t, contexts, 1)
	return contexts[0]
}

func Test_parse_yaml_use_condition_in_resource(t *testing.T) {
	source := `---
AWSTemplateFormatVersion: "2010-09-09"
Description: some description
Parameters:
  ServiceName:
    Type: String
    Description: The service name
  EnvName:
    Type: String
    Description: Optional environment name to prefix all resources with
    Default: ""

Conditions:
  SuffixResources: !Not [!Equals [!Ref EnvName, ""]]

Resources:
  ErrorTimedOutMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      FilterPattern: '?ERROR ?error ?Error ?"timed out"' # If log contains one of these error words or timed out
      LogGroupName:
        !If [
          SuffixResources,
          !Sub "/aws/lambda/${ServiceName}-${EnvName}",
          !Sub "/aws/lambda/${ServiceName}",
        ]
      MetricTransformations:
        - MetricName: !Sub "${ServiceName}-ErrorLogCount"
          MetricNamespace: market-LogMetrics
          MetricValue: 1
          DefaultValue: 0
`

	files, err := parseFile(t, source, "cf.yaml")
	require.NoError(t, err)
	assert.Len(t, files, 1)
	ctx := files[0]

	assert.Len(t, ctx.Parameters, 2)
	assert.Len(t, ctx.Conditions, 1)
	assert.Len(t, ctx.Resources, 1)

	res := ctx.GetResourceByLogicalID("ErrorTimedOutMetricFilter")
	assert.NotNil(t, res)

	refProp := res.GetProperty("LogGroupName")
	assert.False(t, refProp.IsNil())
	assert.Equal(t, "/aws/lambda/${ServiceName}", refProp.AsString())
}
