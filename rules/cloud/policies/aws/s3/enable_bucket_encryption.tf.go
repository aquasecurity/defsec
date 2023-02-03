package s3

var terraformEnableBucketEncryptionGoodExamples = []string{
	`
 resource "aws_s3_bucket" "good_example" {
   bucket = "mybucket"
 
   server_side_encryption_configuration {
     rule {
       apply_server_side_encryption_by_default {
         kms_master_key_id = "arn"
         sse_algorithm     = "aws:kms"
       }
     }
   }
 }
 `, `
 resource "aws_s3_bucket" "good_example" {
   bucket = "mybucket"
 
   # ... other configuration ...
 }
 
 resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
   bucket = aws_s3_bucket.good_example.id
 
   rule {
     apply_server_side_encryption_by_default {
       kms_master_key_id = aws_kms_key.mykey.arn
       sse_algorithm     = "aws:kms"
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

resource "aws_kms_key" "s3_key" {
  description         = "This key is used to encrypt S3 bucket objects"
  enable_key_rotation = true
}

module "s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.0"

  bucket                  = "my_bucket"
  acl                     = "private"
  force_destroy           = true
  restrict_public_buckets = true
  ignore_public_acls      = true
  block_public_policy     = true
  block_public_acls       = true

  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.s3_key.arn
      }
    }
  }

}
`,
}

var terraformEnableBucketEncryptionBadExamples = []string{
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

var terraformEnableBucketEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#enable-default-server-side-encryption`,
}

var terraformEnableBucketEncryptionRemediationMarkdown = ``
