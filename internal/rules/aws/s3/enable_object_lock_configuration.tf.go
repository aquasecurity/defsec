package s3

var terraformEnableObjectLockConfigurationGoodExamples = []string{
	`
 resource "aws_s3_bucket" "good_example" {
   bucket = "mybucket"
 
   object_lock_configuration = {
    object_lock_enabled = "Enabled"

    rule{
      default_retention = {
        mode = "GOVERNANCE"
        days = 366
      }
    }
  }
 }
 `, `
 resource "aws_s3_bucket" "good_example" {
   bucket = "mybucket1"
 
   # ... other configuration ...
 }
 
 resource "aws_s3_bucket_object_lock_configuration" "example" {
   bucket = aws_s3_bucket.good_example.id
 
   object_lock_configuration = {
    object_lock_enabled = "Enabled"

    rule  {
      default_retention = {
        mode = "GOVERNANCE"
        days = 366
      }
    }
  }
 }
 `,
	`
terraform {
  required_version = ">= 1.0, < 2.0"

  required_providers {
    aws = ">= 4.0"
  }
}


`,
}

var terraformEnableObjectLockConfigurationBadExamples = []string{
	`
 resource "aws_s3_bucket" "bad_example" {
   bucket = "mybucket"
 }
 `, `
 resource "aws_s3_bucket" "example" {
   bucket = "yournamehere"
 
   # ... other configuration ...
 }

 `,
}

var terraformEnableObjectLockConfigurationLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_object_lock_configuration`,
}

var terraformEnableObjectLockConfigurationRemediationMarkdown = ``
