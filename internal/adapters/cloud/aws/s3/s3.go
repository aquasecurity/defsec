package s3

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws/arn"
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/state"
	s3api "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/liamg/iamgo"
)

type S3Adapter struct {
	*aws.RootAdapter
	api *s3api.Client
}

func init() {
	aws.RegisterServiceAdapter(&S3Adapter{})
}

func (a *S3Adapter) Provider() string {
	return "aws"
}

func (a *S3Adapter) Name() string {
	return "s3"
}

func (a *S3Adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = s3api.NewFromConfig(root.SessionConfig())

	var err error
	state.AWS.S3.Buckets, err = a.getBuckets()
	if err != nil {
		return err
	}

	return nil
}

func (a *S3Adapter) getBuckets() (buckets []s3.Bucket, err error) {
	apiBuckets, err := a.api.ListBuckets(a.Context(), &s3api.ListBucketsInput{})
	if err != nil {
		return buckets, err
	}

	a.Tracker().SetServiceLabel("Scanning buckets...")
	a.Tracker().SetTotalResources(len(apiBuckets.Buckets))

	for _, bucket := range apiBuckets.Buckets {
		if bucket.Name == nil {
			continue
		}

		bucketMetadata := arn.New("s3", "", "", *bucket.Name).Metadata()

		b := s3.NewBucket(bucketMetadata)
		b.Name = types.String(*bucket.Name, bucketMetadata)
		b.PublicAccessBlock = a.getPublicAccessBlock(bucket.Name, bucketMetadata)
		b.BucketPolicies = a.getBucketPolicies(bucket.Name, bucketMetadata)
		b.Encryption = a.getBucketEncryption(bucket.Name, bucketMetadata)
		b.Versioning = a.getBucketVersioning(bucket.Name, bucketMetadata)
		b.Logging = a.getBucketLogging(bucket.Name, bucketMetadata)
		b.ACL = a.getBucketACL(bucket.Name, bucketMetadata)

		buckets = append(buckets, b)
		a.Tracker().IncrementResource()
	}

	return buckets, nil
}

func (a *S3Adapter) getPublicAccessBlock(bucketName *string, metadata types.Metadata) *s3.PublicAccessBlock {

	publicAccessBlocks, err := a.api.GetPublicAccessBlock(a.Context(), &s3api.GetPublicAccessBlockInput{
		Bucket: bucketName,
	})
	if err != nil {
		return nil
	}

	if publicAccessBlocks == nil {
		return nil
	}

	config := publicAccessBlocks.PublicAccessBlockConfiguration
	pab := s3.NewPublicAccessBlock(metadata)

	pab.BlockPublicACLs = types.Bool(config.BlockPublicAcls, metadata)
	pab.BlockPublicPolicy = types.Bool(config.BlockPublicPolicy, metadata)
	pab.IgnorePublicACLs = types.Bool(config.IgnorePublicAcls, metadata)
	pab.RestrictPublicBuckets = types.Bool(config.RestrictPublicBuckets, metadata)

	return &pab
}

func (a *S3Adapter) getBucketPolicies(bucketName *string, metadata types.Metadata) []iam.Policy {
	var bucketPolicies []iam.Policy

	bucketPolicy, err := a.api.GetBucketPolicy(a.Context(), &s3api.GetBucketPolicyInput{Bucket: bucketName})
	if err != nil {
		return bucketPolicies
	}

	if bucketPolicy.Policy != nil {
		policyDocument, err := iamgo.ParseString(*bucketPolicy.Policy)
		if err != nil {
			return bucketPolicies
		}

		bucketPolicies = append(bucketPolicies, iam.Policy{
			Metadata: metadata,
			Document: iam.Document{
				Metadata: metadata,
				Parsed:   *policyDocument,
			},
		})
	}

	return bucketPolicies

}

func (a *S3Adapter) getBucketEncryption(bucketName *string, metadata types.Metadata) s3.Encryption {
	bucketEncryption := s3.Encryption{
		Metadata:  metadata,
		Enabled:   types.BoolDefault(false, metadata),
		Algorithm: types.StringDefault("", metadata),
		KMSKeyId:  types.StringDefault("", metadata),
	}

	encryption, err := a.api.GetBucketEncryption(a.Context(), &s3api.GetBucketEncryptionInput{Bucket: bucketName})
	if err != nil {
		return bucketEncryption
	}

	if encryption.ServerSideEncryptionConfiguration != nil && len(encryption.ServerSideEncryptionConfiguration.Rules) > 0 {
		defaultEncryption := encryption.ServerSideEncryptionConfiguration.Rules[0]
		bucketEncryption.Enabled = types.Bool(defaultEncryption.BucketKeyEnabled, metadata)
		algorithm := defaultEncryption.ApplyServerSideEncryptionByDefault.SSEAlgorithm
		bucketEncryption.Algorithm = types.StringDefault(string(algorithm), metadata)
		kmsKeyId := defaultEncryption.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
		if kmsKeyId != nil {
			bucketEncryption.KMSKeyId = types.StringDefault(*kmsKeyId, metadata)
		}
	}

	return bucketEncryption
}

func (a *S3Adapter) getBucketVersioning(bucketName *string, metadata types.Metadata) s3.Versioning {
	bucketVersioning := s3.Versioning{
		Metadata: metadata,
		Enabled:  types.BoolDefault(false, metadata),
	}

	versioning, err := a.api.GetBucketVersioning(a.Context(), &s3api.GetBucketVersioningInput{Bucket: bucketName})
	if err != nil {
		return bucketVersioning
	}

	if versioning.Status == s3types.BucketVersioningStatusEnabled {
		bucketVersioning.Enabled = types.Bool(true, metadata)
	}

	return bucketVersioning
}

func (a *S3Adapter) getBucketLogging(bucketName *string, metadata types.Metadata) s3.Logging {

	bucketLogging := s3.Logging{
		Metadata:     metadata,
		Enabled:      types.BoolDefault(false, metadata),
		TargetBucket: types.StringDefault("", metadata),
	}

	logging, err := a.api.GetBucketLogging(a.Context(), &s3api.GetBucketLoggingInput{Bucket: bucketName})
	if err != nil {
		return bucketLogging
	}

	if logging.LoggingEnabled != nil {
		bucketLogging.Enabled = types.Bool(true, metadata)
		bucketLogging.TargetBucket = types.StringDefault(*logging.LoggingEnabled.TargetBucket, metadata)
	}

	return bucketLogging
}

func (a *S3Adapter) getBucketACL(bucketName *string, metadata types.Metadata) types.StringValue {
	acl, err := a.api.GetBucketAcl(a.Context(), &s3api.GetBucketAclInput{Bucket: bucketName})
	if err != nil {
		return types.StringDefault("private", metadata)
	}

	aclValue := "private"

	for _, grant := range acl.Grants {
		if grant.Grantee != nil && grant.Grantee.DisplayName != nil {
			if *grant.Grantee.DisplayName == "AuthenticatedUsers" {
				aclValue = "authenticated-read"
				break
			}
		}
	}

	return types.String(aclValue, metadata)
}
