package s3

import (
	"strings"

	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go/aws/awserr"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/state"
	s3api "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/liamg/iamgo"
)

type adapter struct {
	*aws.RootAdapter
	api *s3api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "s3"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = s3api.NewFromConfig(root.SessionConfig())

	var err error
	state.AWS.S3.Buckets, err = a.getBuckets()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getBuckets() (buckets []s3.Bucket, err error) {
	a.Tracker().SetServiceLabel("Discovering buckets...")
	apiBuckets, err := a.api.ListBuckets(a.Context(), &s3api.ListBucketsInput{})
	if err != nil {
		return buckets, err
	}

	a.Tracker().SetTotalResources(len(apiBuckets.Buckets))
	a.Tracker().SetServiceLabel("Discovering buckets...")
	return concurrency.Adapt(apiBuckets.Buckets, a.RootAdapter, a.adaptBucket), nil
}

func (a *adapter) adaptBucket(bucket s3types.Bucket) (*s3.Bucket, error) {

	if bucket.Name == nil {
		return nil, nil
	}

	location, err := a.api.GetBucketLocation(a.Context(), &s3api.GetBucketLocationInput{
		Bucket: bucket.Name,
	})
	if err != nil {
		a.Debug("Error getting bucket location: %s", err)
		return nil, nil
	}
	region := string(location.LocationConstraint)
	if region == "" { // Region us-east-1 have a LocationConstraint of null (???)
		region = "us-east-1"
	}
	if region != a.Region() {
		return nil, nil
	}

	bucketMetadata := a.CreateMetadata(*bucket.Name)

	name := defsecTypes.StringDefault("", bucketMetadata)
	if bucket.Name != nil {
		name = defsecTypes.String(*bucket.Name, bucketMetadata)
	}

	b := s3.Bucket{
		Metadata:          bucketMetadata,
		Name:              name,
		PublicAccessBlock: a.getPublicAccessBlock(bucket.Name, bucketMetadata),
		BucketPolicies:    a.getBucketPolicies(bucket.Name, bucketMetadata),
		Encryption:        a.getBucketEncryption(bucket.Name, bucketMetadata),
		Versioning:        a.getBucketVersioning(bucket.Name, bucketMetadata),
		Logging:           a.getBucketLogging(bucket.Name, bucketMetadata),
		ACL:               a.getBucketACL(bucket.Name, bucketMetadata),
	}

	return &b, nil

}

func (a *adapter) getPublicAccessBlock(bucketName *string, metadata defsecTypes.Metadata) *s3.PublicAccessBlock {

	publicAccessBlocks, err := a.api.GetPublicAccessBlock(a.Context(), &s3api.GetPublicAccessBlockInput{
		Bucket: bucketName,
	})
	if err != nil {
		// nolint
		if awsError, ok := err.(awserr.Error); ok {
			if awsError.Code() == "NoSuchPublicAccessBlockConfiguration" {
				return nil
			}
		}
		a.Debug("Error getting public access block: %s", err)
		return nil
	}

	if publicAccessBlocks == nil {
		return nil
	}

	config := publicAccessBlocks.PublicAccessBlockConfiguration
	pab := s3.NewPublicAccessBlock(metadata)

	pab.BlockPublicACLs = defsecTypes.Bool(config.BlockPublicAcls, metadata)
	pab.BlockPublicPolicy = defsecTypes.Bool(config.BlockPublicPolicy, metadata)
	pab.IgnorePublicACLs = defsecTypes.Bool(config.IgnorePublicAcls, metadata)
	pab.RestrictPublicBuckets = defsecTypes.Bool(config.RestrictPublicBuckets, metadata)

	return &pab
}

func (a *adapter) getBucketPolicies(bucketName *string, metadata defsecTypes.Metadata) []iam.Policy {
	var bucketPolicies []iam.Policy

	bucketPolicy, err := a.api.GetBucketPolicy(a.Context(), &s3api.GetBucketPolicyInput{Bucket: bucketName})
	if err != nil {
		// nolint
		if awsError, ok := err.(awserr.Error); ok {
			if awsError.Code() == "NoSuchBucketPolicy" {
				return nil
			}
		}
		a.Debug("Error getting public access block: %s", err)
		return nil

	}

	if bucketPolicy.Policy != nil {
		policyDocument, err := iamgo.ParseString(*bucketPolicy.Policy)
		if err != nil {
			a.Debug("Error parsing bucket policy: %s", err)
			return bucketPolicies
		}

		bucketPolicies = append(bucketPolicies, iam.Policy{
			Metadata: metadata,
			Name:     defsecTypes.StringDefault("", metadata),
			Document: iam.Document{
				Metadata: metadata,
				Parsed:   *policyDocument,
			},
			Builtin: defsecTypes.Bool(false, metadata),
		})
	}

	return bucketPolicies

}

func (a *adapter) getBucketEncryption(bucketName *string, metadata defsecTypes.Metadata) s3.Encryption {
	bucketEncryption := s3.Encryption{
		Metadata:  metadata,
		Enabled:   defsecTypes.BoolDefault(false, metadata),
		Algorithm: defsecTypes.StringDefault("", metadata),
		KMSKeyId:  defsecTypes.StringDefault("", metadata),
	}

	encryption, err := a.api.GetBucketEncryption(a.Context(), &s3api.GetBucketEncryptionInput{Bucket: bucketName})
	if err != nil {
		// nolint
		if awsError, ok := err.(awserr.Error); ok {
			if awsError.Code() == "ServerSideEncryptionConfigurationNotFoundError" {
				return bucketEncryption
			}
		}
		a.Debug("Error getting encryption block: %s", err)
		return bucketEncryption
	}

	if encryption.ServerSideEncryptionConfiguration != nil && len(encryption.ServerSideEncryptionConfiguration.Rules) > 0 {
		defaultEncryption := encryption.ServerSideEncryptionConfiguration.Rules[0]
		algorithm := defaultEncryption.ApplyServerSideEncryptionByDefault.SSEAlgorithm
		if algorithm != "" {
			bucketEncryption.Enabled = defsecTypes.Bool(true, metadata)
		}
		bucketEncryption.Algorithm = defsecTypes.StringDefault(string(algorithm), metadata)
		kmsKeyId := defaultEncryption.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
		if kmsKeyId != nil {
			bucketEncryption.KMSKeyId = defsecTypes.StringDefault(*kmsKeyId, metadata)
		}
	}

	return bucketEncryption
}

func (a *adapter) getBucketVersioning(bucketName *string, metadata defsecTypes.Metadata) s3.Versioning {
	bucketVersioning := s3.Versioning{
		Metadata:  metadata,
		Enabled:   defsecTypes.BoolDefault(false, metadata),
		MFADelete: defsecTypes.BoolDefault(false, metadata),
	}

	versioning, err := a.api.GetBucketVersioning(a.Context(), &s3api.GetBucketVersioningInput{Bucket: bucketName})
	if err != nil {
		// nolint
		if awsError, ok := err.(awserr.Error); ok {
			if awsError.Code() == "NotImplemented" {
				return bucketVersioning
			}
		}
		a.Debug("Error getting bucket versioning: %s", err)
		return bucketVersioning
	}

	if versioning.Status == s3types.BucketVersioningStatusEnabled {
		bucketVersioning.Enabled = defsecTypes.Bool(true, metadata)
	}

	bucketVersioning.MFADelete = defsecTypes.Bool(versioning.MFADelete == s3types.MFADeleteStatusEnabled, metadata)

	return bucketVersioning
}

func (a *adapter) getBucketLogging(bucketName *string, metadata defsecTypes.Metadata) s3.Logging {

	bucketLogging := s3.Logging{
		Metadata:     metadata,
		Enabled:      defsecTypes.BoolDefault(false, metadata),
		TargetBucket: defsecTypes.StringDefault("", metadata),
	}

	logging, err := a.api.GetBucketLogging(a.Context(), &s3api.GetBucketLoggingInput{Bucket: bucketName})
	if err != nil {
		a.Debug("Error getting bucket logging: %s", err)
		return bucketLogging
	}

	if logging.LoggingEnabled != nil {
		bucketLogging.Enabled = defsecTypes.Bool(true, metadata)
		bucketLogging.TargetBucket = defsecTypes.StringDefault(*logging.LoggingEnabled.TargetBucket, metadata)
	}

	return bucketLogging
}

func (a *adapter) getBucketACL(bucketName *string, metadata defsecTypes.Metadata) defsecTypes.StringValue {
	acl, err := a.api.GetBucketAcl(a.Context(), &s3api.GetBucketAclInput{Bucket: bucketName})
	if err != nil {
		a.Debug("Error getting bucket ACL: %s", err)
		return defsecTypes.StringDefault("private", metadata)
	}

	aclValue := "private"

	for _, grant := range acl.Grants {
		if grant.Grantee != nil && grant.Grantee.Type == "Group" {
			switch grant.Permission {
			case s3types.PermissionWrite, s3types.PermissionWriteAcp:
				aclValue = "public-read-write"
			case s3types.PermissionRead, s3types.PermissionReadAcp:
				if strings.HasSuffix(*grant.Grantee.URI, "AuthenticatedUsers") {
					aclValue = "authenticated-read"
				} else {
					aclValue = "public-read"
				}
			}
		}
	}

	return defsecTypes.String(aclValue, metadata)
}
