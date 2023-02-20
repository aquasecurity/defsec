package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/pkg/framework"
	registered "github.com/aquasecurity/defsec/pkg/rules"
)

func init() { // change the pwd for the test to top level defesc dir
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../..")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}
}

func Test_AVDPageGeneration(t *testing.T) {
	tmpDir := t.TempDir()
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	var generateCount int
	for _, metadata := range registered.GetRegistered(framework.ALL) {
		writeDocsFile(metadata, tmpDir)
		generateCount++
	}
	fmt.Printf("\nGenerated %d files in avd_docs\n", generateCount)

	// check golang policies
	b, err := os.ReadFile(filepath.Join(tmpDir, "aws/rds/AVD-AWS-0077", "Terraform.md"))
	require.NoError(t, err)
	assert.Contains(t, string(b), `hcl
 resource "aws_rds_cluster" "good_example" {
 	cluster_identifier      = "aurora-cluster-demo"
 	engine                  = "aurora-mysql"
 	engine_version          = "5.7.mysql_aurora.2.03.2"
 	availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
 	database_name           = "mydb"
 	master_username         = "foo"
 	master_password         = "bar"
 	backup_retention_period = 5
 	preferred_backup_window = "07:00-09:00"
   }`)

	b, err = os.ReadFile(filepath.Join(tmpDir, "aws/rds/AVD-AWS-0077", "CloudFormation.md"))
	require.NoError(t, err)
	assert.Contains(t, string(b), `yaml---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      BackupRetentionPeriod: 30
`)

	// check rego policies
	b, err = os.ReadFile(filepath.Join(tmpDir, "aws/rds/AVD-AWS-0180", "Terraform.md"))
	require.NoError(t, err)
	assert.Contains(t, string(b), `hcl
 resource "aws_db_instance" "good_example" {
 	publicly_accessible = false
 }`)

	b, err = os.ReadFile(filepath.Join(tmpDir, "aws/rds/AVD-AWS-0180", "CloudFormation.md"))
	require.NoError(t, err)
	assert.Contains(t, string(b), `yaml---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: false`)
}
