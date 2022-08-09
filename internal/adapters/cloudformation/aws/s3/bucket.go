package s3

import (
	"regexp"
	"strings"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

var aclConvertRegex = regexp.MustCompile(`[A-Z][^A-Z]*`)

func getBuckets(cfFile parser.FileContext) []s3.Bucket {
	var buckets []s3.Bucket
	bucketResources := cfFile.GetResourcesByType("AWS::S3::Bucket")

	for _, r := range bucketResources {
		s3b := s3.Bucket{
			Metadata:          r.Metadata(),
			Name:              r.GetStringProperty("BucketName"),
			PublicAccessBlock: getPublicAccessBlock(r),
			Encryption:        getEncryption(r, cfFile),
			Versioning: s3.Versioning{
				Metadata: r.Metadata(),
				Enabled:  hasVersioning(r),
			},
			Logging: getLogging(r),
			ACL:     convertAclValue(r.GetStringProperty("AccessControl", "private")),
		}

		buckets = append(buckets, s3b)
	}
	return buckets
}

func getPublicAccessBlock(r *parser.Resource) *s3.PublicAccessBlock {
	if block := r.GetProperty("PublicAccessBlockConfiguration"); block.IsNil() {
		return nil
	}

	return &s3.PublicAccessBlock{
		Metadata:              r.Metadata(),
		BlockPublicACLs:       r.GetBoolProperty("PublicAccessBlockConfiguration.BlockPublicAcls"),
		BlockPublicPolicy:     r.GetBoolProperty("PublicAccessBlockConfiguration.BlockPublicPolicy"),
		IgnorePublicACLs:      r.GetBoolProperty("PublicAccessBlockConfiguration.IgnorePublicAcls"),
		RestrictPublicBuckets: r.GetBoolProperty("PublicAccessBlockConfiguration.RestrictPublicBuckets"),
	}
}

func convertAclValue(aclValue types2.StringValue) types2.StringValue {
	matches := aclConvertRegex.FindAllString(aclValue.Value(), -1)

	return types2.String(strings.ToLower(strings.Join(matches, "-")), aclValue.GetMetadata())
}

func getLogging(r *parser.Resource) s3.Logging {

	logging := s3.Logging{
		Metadata:     r.Metadata(),
		Enabled:      types2.BoolDefault(false, r.Metadata()),
		TargetBucket: types2.StringDefault("", r.Metadata()),
	}

	if config := r.GetProperty("LoggingConfiguration"); config.IsNotNil() {
		logging.TargetBucket = config.GetStringProperty("DestinationBucketName")
		if logging.TargetBucket.IsNotEmpty() || !logging.TargetBucket.GetMetadata().IsResolvable() {
			logging.Enabled = types2.Bool(true, config.Metadata())
		}
	}
	return logging
}

func hasVersioning(r *parser.Resource) types2.BoolValue {
	versioningProp := r.GetProperty("VersioningConfiguration.Status")

	if versioningProp.IsNil() {
		return types2.BoolDefault(false, r.Metadata())
	}

	versioningEnabled := false
	if versioningProp.EqualTo("Enabled") {
		versioningEnabled = true

	}
	return types2.Bool(versioningEnabled, versioningProp.Metadata())
}

func getEncryption(r *parser.Resource, _ parser.FileContext) s3.Encryption {

	encryption := s3.Encryption{
		Metadata:  r.Metadata(),
		Enabled:   types2.BoolDefault(false, r.Metadata()),
		Algorithm: types2.StringDefault("", r.Metadata()),
		KMSKeyId:  types2.StringDefault("", r.Metadata()),
	}

	if encryptProps := r.GetProperty("BucketEncryption.ServerSideEncryptionConfiguration"); encryptProps.IsNotNil() {
		for _, rule := range encryptProps.AsList() {
			if algo := rule.GetProperty("ServerSideEncryptionByDefault.SSEAlgorithm"); algo.EqualTo("AES256") {
				encryption.Enabled = types2.Bool(true, algo.Metadata())
			} else if kmsKeyProp := rule.GetProperty("ServerSideEncryptionByDefault.KMSMasterKeyID"); !kmsKeyProp.IsEmpty() && kmsKeyProp.IsString() {
				encryption.KMSKeyId = kmsKeyProp.AsStringValue()
			}
			if encryption.Enabled.IsFalse() {
				encryption.Enabled = rule.GetBoolProperty("BucketKeyEnabled", false)
			}
		}
	}

	return encryption
}
