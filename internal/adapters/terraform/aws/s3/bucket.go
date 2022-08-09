package s3

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/terraform"
	types2 "github.com/aquasecurity/defsec/pkg/types"
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
		Enabled:   types2.BoolDefault(false, block.GetMetadata()),
		KMSKeyId:  types2.StringDefault("", block.GetMetadata()),
		Algorithm: types2.StringDefault("", block.GetMetadata()),
	}
}

func getVersioning(block *terraform.Block, a *adapter) s3.Versioning {
	if block.HasChild("versioning") {
		return s3.Versioning{
			Metadata: block.GetMetadata(),
			Enabled:  isVersioned(block),
		}
	}
	for _, versioningResource := range a.modules.GetResourcesByType("aws_s3_bucket_versioning") {
		bucketAttr := versioningResource.GetAttribute("bucket")
		if bucketAttr.IsNotNil() {
			if referencedBlock, err := a.modules.GetReferencedBlock(bucketAttr, versioningResource); err == nil {
				if referencedBlock.ID() == block.ID() {
					return s3.Versioning{
						Metadata: versioningResource.GetMetadata(),
						Enabled:  isVersioned(versioningResource),
					}
				}
			}
		}
	}

	return s3.Versioning{
		Metadata: block.GetMetadata(),
		Enabled:  types2.BoolDefault(false, block.GetMetadata()),
	}
}

func getLogging(block *terraform.Block, a *adapter) s3.Logging {
	if loggingBlock := block.GetBlock("logging"); loggingBlock.IsNotNil() {
		targetBucket := loggingBlock.GetAttribute("target_bucket").AsStringValueOrDefault("", loggingBlock)
		if referencedBlock, err := a.modules.GetReferencedBlock(loggingBlock.GetAttribute("target_bucket"), loggingBlock); err == nil {
			targetBucket = types2.String(referencedBlock.FullName(), loggingBlock.GetAttribute("target_bucket").GetMetadata())
		}
		return s3.Logging{
			Metadata:     loggingBlock.GetMetadata(),
			Enabled:      types2.Bool(true, loggingBlock.GetMetadata()),
			TargetBucket: targetBucket,
		}
	}

	for _, loggingResource := range a.modules.GetResourcesByType("aws_s3_bucket_logging") {
		bucketAttr := loggingResource.GetAttribute("bucket")
		if bucketAttr.IsNotNil() {
			targetBucket := loggingResource.GetAttribute("target-bucket").AsStringValueOrDefault("", loggingResource)
			if referencedBlock, err := a.modules.GetReferencedBlock(loggingResource.GetAttribute("target_bucket"), loggingResource); err == nil {
				targetBucket = types2.String(referencedBlock.FullName(), loggingResource.GetAttribute("target_bucket").GetMetadata())
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
		Enabled:      types2.Bool(false, block.GetMetadata()),
		TargetBucket: types2.StringDefault("", block.GetMetadata()),
	}
}

func getBucketAcl(block *terraform.Block, a *adapter) types2.StringValue {
	aclAttr := block.GetAttribute("acl")
	if aclAttr.IsString() {
		return aclAttr.AsStringValueOrDefault("private", block)
	}

	for _, aclResource := range a.modules.GetResourcesByType("aws_s3_bucket_acl") {
		bucketAttr := aclResource.GetAttribute("bucket")

		if bucketAttr.IsNotNil() {
			if referencedBlock, err := a.modules.GetReferencedBlock(bucketAttr, aclResource); err == nil {
				if referencedBlock.ID() == block.ID() {
					return aclResource.GetAttribute("acl").AsStringValueOrDefault("private", aclResource)
				}
			}
		}
	}
	return types2.StringDefault("private", block.GetMetadata())
}

func isEncrypted(encryptionBlock *terraform.Block) types2.BoolValue {
	ruleBlock := encryptionBlock.GetBlock("rule")
	if ruleBlock.IsNil() {
		return types2.BoolDefault(false, encryptionBlock.GetMetadata())
	}
	defaultBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default")
	if defaultBlock.IsNil() {
		return types2.BoolDefault(false, ruleBlock.GetMetadata())
	}
	sseAlgorithm := defaultBlock.GetAttribute("sse_algorithm")
	if sseAlgorithm.IsNil() {
		return types2.BoolDefault(false, defaultBlock.GetMetadata())
	}
	return types2.Bool(
		true,
		sseAlgorithm.GetMetadata(),
	)
}

func hasLogging(b *terraform.Block) types2.BoolValue {
	if loggingBlock := b.GetBlock("logging"); loggingBlock.IsNotNil() {
		if targetAttr := loggingBlock.GetAttribute("target_bucket"); targetAttr.IsNotNil() && targetAttr.IsNotEmpty() {
			return types2.Bool(true, targetAttr.GetMetadata())
		}
		return types2.BoolDefault(false, loggingBlock.GetMetadata())
	}
	if targetBucket := b.GetAttribute("target_bucket"); targetBucket.IsNotNil() {
		return types2.Bool(true, targetBucket.GetMetadata())
	}
	return types2.BoolDefault(false, b.GetMetadata())
}

func isVersioned(b *terraform.Block) types2.BoolValue {
	if versioningBlock := b.GetBlock("versioning"); versioningBlock.IsNotNil() {
		return versioningBlock.GetAttribute("enabled").AsBoolValueOrDefault(true, versioningBlock)
	}
	if versioningBlock := b.GetBlock("versioning_configuration"); versioningBlock.IsNotNil() {
		status := versioningBlock.GetAttribute("status")
		if status.Equals("Enabled", terraform.IgnoreCase) {
			return types2.Bool(true, status.GetMetadata())
		} else {
			return types2.Bool(false, b.GetMetadata())
		}
	}
	return types2.BoolDefault(
		false,
		b.GetMetadata(),
	)
}
