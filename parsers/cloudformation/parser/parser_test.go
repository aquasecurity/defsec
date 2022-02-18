package parser

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/defsec/parsers/testutil"
	"github.com/aquasecurity/defsec/parsers/testutil/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	testFile := testutil.CreateTestFile(source, testutil.YamlTestFileExt)
	defer func() { _ = os.RemoveAll(testFile) }()

	files, err := New().ParseFiles(testFile)
	require.NoError(t, err)
	assert.Len(t, files, 1)
	file := files[0]

	assert.Len(t, file.Resources, 1)
	assert.Len(t, file.Parameters, 2)
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

	testFile := testutil.CreateTestFile(source, testutil.JsonTestFileExt)
	defer func() { _ = os.RemoveAll(testFile) }()

	files, err := New().ParseFiles(testFile)
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

	testFile := testutil.CreateTestFile(source, testutil.YamlTestFileExt)
	defer func() { _ = os.RemoveAll(testFile) }()

	files, err := New().ParseFiles(testFile)
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

	testFile := testutil.CreateTestFile(source, testutil.YamlTestFileExt)
	defer func() { _ = os.RemoveAll(testFile) }()

	files, err := New().ParseFiles(testFile)
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

	fs, err := filesystem.New()
	require.NoError(t, err)
	defer fs.Close()

	source = strings.TrimSpace(strings.ReplaceAll(source, "\t", "  "))

	ext := "yaml"
	if source[0] == '{' {
		ext = "json"
	}

	filename := fmt.Sprintf("test.%s", ext)

	if err := fs.WriteTextFile(filename, source); err != nil {
		t.Fatal(err)
	}

	fileContext, err := New().Parse(bytes.NewReader([]byte(source)), filename)
	require.NoError(t, err)
	return fileContext
}
