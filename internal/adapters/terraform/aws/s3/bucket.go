package s3

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type adapter struct {
	modules   terraform.Modules
	bucketMap map[string]*s3.Bucket
}

func (a *adapter) adaptBuckets() []s3.Bucket {
	for _, block := range a.modules.GetResourcesByType("aws_s3_bucket") {
		bucket := &s3.Bucket{
			Metadata:          block.GetMetadata(),
			Name:              block.GetAttribute("bucket").AsStringValueOrDefault("", block),
			PublicAccessBlock: nil,
			BucketPolicies:    nil,
			Encryption:        getEncryption(block, a),
			Versioning:        getVersioning(block, a),
			Logging:           getLogging(block, a),
			ACL:               getBucketAcl(block, a),
		}
		a.bucketMap[block.ID()] = bucket
	}

	a.adaptBucketPolicies()
	a.adaptPublicAccessBlocks()

	var buckets []s3.Bucket
	for _, bucket := range a.bucketMap {
		buckets = append(buckets, *bucket)
	}

	return buckets
}

func getEncryption(block *terraform.Block, a *adapter) s3.Encryption {
	if block.HasChild("server_side_encryption_configuration") {
		return s3.Encryption{
			Metadata:  block.GetMetadata(),
			Enabled:   isEncrypted(block.GetBlock("server_side_encryption_configuration")),
			Algorithm: block.GetNestedAttribute("server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm").AsStringValueOrDefault("", block),
			KMSKeyId:  block.GetNestedAttribute("server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.kms_master_key_id").AsStringValueOrDefault("", block),
		}
	}
	for _, encryptionResource := range a.modules.GetResourcesByType("aws_s3_bucket_server_side_encryption_configuration") {
		bucketAttr := encryptionResource.GetAttribute("bucket")
		if bucketAttr.IsNotNil() {
			if bucketAttr.IsString() {
				actualBucketName := block.GetAttribute("bucket").AsStringValueOrDefault("", block).Value()
				if bucketAttr.Equals(block.ID()) || bucketAttr.Equals(actualBucketName) {
					return s3.Encryption{
						Metadata:  encryptionResource.GetMetadata(),
						Enabled:   isEncrypted(encryptionResource),
						Algorithm: encryptionResource.GetNestedAttribute("rule.apply_server_side_encryption_by_default.sse_algorithm").AsStringValueOrDefault("", block),
						KMSKeyId:  encryptionResource.GetNestedAttribute("rule.apply_server_side_encryption_by_default.kms_master_key_id").AsStringValueOrDefault("", block),
					}
				}
			}
			if referencedBlock, err := a.modules.GetReferencedBlock(bucketAttr, encryptionResource); err == nil {
				if referencedBlock.ID() == block.ID() {
					return s3.Encryption{
						Metadata:  encryptionResource.GetMetadata(),
						Enabled:   isEncrypted(encryptionResource),
						Algorithm: encryptionResource.GetNestedAttribute("rule.apply_server_side_encryption_by_default.sse_algorithm").AsStringValueOrDefault("", block),
						KMSKeyId:  encryptionResource.GetNestedAttribute("rule.apply_server_side_encryption_by_default.kms_master_key_id").AsStringValueOrDefault("", block),
					}
				}
			}
		}
	}
	return s3.Encryption{
		Metadata:  block.GetMetadata(),
		Enabled:   defsecTypes.BoolDefault(false, block.GetMetadata()),
		KMSKeyId:  defsecTypes.StringDefault("", block.GetMetadata()),
		Algorithm: defsecTypes.StringDefault("", block.GetMetadata()),
	}
}

func getVersioning(block *terraform.Block, a *adapter) s3.Versioning {
	versioning := s3.Versioning{
		Metadata:  block.GetMetadata(),
		Enabled:   defsecTypes.BoolDefault(false, block.GetMetadata()),
		MFADelete: defsecTypes.BoolDefault(false, block.GetMetadata()),
	}
	if vBlock := block.GetBlock("versioning"); vBlock != nil {
		versioning.Enabled = vBlock.GetAttribute("enabled").AsBoolValueOrDefault(true, vBlock)
		versioning.MFADelete = vBlock.GetAttribute("mfa_delete").AsBoolValueOrDefault(false, vBlock)
	}
	for _, versioningResource := range a.modules.GetResourcesByType("aws_s3_bucket_versioning") {
		bucketAttr := versioningResource.GetAttribute("bucket")
		if bucketAttr.IsNotNil() {
			if bucketAttr.IsString() {
				actualBucketName := block.GetAttribute("bucket").AsStringValueOrDefault("", block).Value()
				if bucketAttr.Equals(block.ID()) || bucketAttr.Equals(actualBucketName) {
					return getVersioningFromResource(versioningResource)
				}
			}
			if referencedBlock, err := a.modules.GetReferencedBlock(bucketAttr, versioningResource); err == nil {
				if referencedBlock.ID() == block.ID() {
					return getVersioningFromResource(versioningResource)
				}
			}
		}
	}
	return versioning
}

// from aws_s3_bucket_versioning
func getVersioningFromResource(block *terraform.Block) s3.Versioning {
	versioning := s3.Versioning{
		Metadata:  block.GetMetadata(),
		Enabled:   defsecTypes.BoolDefault(false, block.GetMetadata()),
		MFADelete: defsecTypes.BoolDefault(false, block.GetMetadata()),
	}
	if config := block.GetBlock("versioning_configuration"); config != nil {
		if status := config.GetAttribute("status"); status.IsNotNil() {
			versioning.Enabled = defsecTypes.Bool(status.Equals("Enabled", terraform.IgnoreCase), status.GetMetadata())
		}
		if mfa := config.GetAttribute("mfa_delete"); mfa.IsNotNil() {
			versioning.MFADelete = defsecTypes.Bool(mfa.Equals("Enabled", terraform.IgnoreCase), mfa.GetMetadata())
		}
	}
	return versioning
}

func getLogging(block *terraform.Block, a *adapter) s3.Logging {
	if loggingBlock := block.GetBlock("logging"); loggingBlock.IsNotNil() {
		targetBucket := loggingBlock.GetAttribute("target_bucket").AsStringValueOrDefault("", loggingBlock)
		if referencedBlock, err := a.modules.GetReferencedBlock(loggingBlock.GetAttribute("target_bucket"), loggingBlock); err == nil {
			targetBucket = defsecTypes.String(referencedBlock.FullName(), loggingBlock.GetAttribute("target_bucket").GetMetadata())
		}
		return s3.Logging{
			Metadata:     loggingBlock.GetMetadata(),
			Enabled:      defsecTypes.Bool(true, loggingBlock.GetMetadata()),
			TargetBucket: targetBucket,
		}
	}

	for _, loggingResource := range a.modules.GetResourcesByType("aws_s3_bucket_logging") {
		bucketAttr := loggingResource.GetAttribute("bucket")
		if bucketAttr.IsNotNil() {
			targetBucket := loggingResource.GetAttribute("target-bucket").AsStringValueOrDefault("", loggingResource)
			if referencedBlock, err := a.modules.GetReferencedBlock(loggingResource.GetAttribute("target_bucket"), loggingResource); err == nil {
				targetBucket = defsecTypes.String(referencedBlock.FullName(), loggingResource.GetAttribute("target_bucket").GetMetadata())
			}
			if bucketAttr.IsString() {
				actualBucketName := block.GetAttribute("bucket").AsStringValueOrDefault("", block).Value()
				if bucketAttr.Equals(block.ID()) || bucketAttr.Equals(actualBucketName) {
					return s3.Logging{
						Metadata:     loggingResource.GetMetadata(),
						Enabled:      hasLogging(loggingResource),
						TargetBucket: targetBucket,
					}
				}
			}
			if referencedBlock, err := a.modules.GetReferencedBlock(bucketAttr, loggingResource); err == nil {
				if referencedBlock.ID() == block.ID() {
					return s3.Logging{
						Metadata:     loggingResource.GetMetadata(),
						Enabled:      hasLogging(loggingResource),
						TargetBucket: targetBucket,
					}
				}
			}
		}
	}

	return s3.Logging{
		Metadata:     block.GetMetadata(),
		Enabled:      defsecTypes.Bool(false, block.GetMetadata()),
		TargetBucket: defsecTypes.StringDefault("", block.GetMetadata()),
	}
}

func getBucketAcl(block *terraform.Block, a *adapter) defsecTypes.StringValue {
	aclAttr := block.GetAttribute("acl")
	if aclAttr.IsString() {
		return aclAttr.AsStringValueOrDefault("private", block)
	}

	for _, aclResource := range a.modules.GetResourcesByType("aws_s3_bucket_acl") {
		bucketAttr := aclResource.GetAttribute("bucket")

		if bucketAttr.IsNotNil() {
			if bucketAttr.IsString() {
				actualBucketName := block.GetAttribute("bucket").AsStringValueOrDefault("", block).Value()
				if bucketAttr.Equals(block.ID()) || bucketAttr.Equals(actualBucketName) {
					return aclResource.GetAttribute("acl").AsStringValueOrDefault("private", aclResource)
				}
			}
			if referencedBlock, err := a.modules.GetReferencedBlock(bucketAttr, aclResource); err == nil {
				if referencedBlock.ID() == block.ID() {
					return aclResource.GetAttribute("acl").AsStringValueOrDefault("private", aclResource)
				}
			}
		}
	}
	return defsecTypes.StringDefault("private", block.GetMetadata())
}

func isEncrypted(encryptionBlock *terraform.Block) defsecTypes.BoolValue {
	ruleBlock := encryptionBlock.GetBlock("rule")
	if ruleBlock.IsNil() {
		return defsecTypes.BoolDefault(false, encryptionBlock.GetMetadata())
	}
	defaultBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default")
	if defaultBlock.IsNil() {
		return defsecTypes.BoolDefault(false, ruleBlock.GetMetadata())
	}
	sseAlgorithm := defaultBlock.GetAttribute("sse_algorithm")
	if sseAlgorithm.IsNil() {
		return defsecTypes.BoolDefault(false, defaultBlock.GetMetadata())
	}
	return defsecTypes.Bool(
		true,
		sseAlgorithm.GetMetadata(),
	)
}

func hasLogging(b *terraform.Block) defsecTypes.BoolValue {
	if loggingBlock := b.GetBlock("logging"); loggingBlock.IsNotNil() {
		if targetAttr := loggingBlock.GetAttribute("target_bucket"); targetAttr.IsNotNil() && targetAttr.IsNotEmpty() {
			return defsecTypes.Bool(true, targetAttr.GetMetadata())
		}
		return defsecTypes.BoolDefault(false, loggingBlock.GetMetadata())
	}
	if targetBucket := b.GetAttribute("target_bucket"); targetBucket.IsNotNil() {
		return defsecTypes.Bool(true, targetBucket.GetMetadata())
	}
	return defsecTypes.BoolDefault(false, b.GetMetadata())
}
