package s3

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws/test"
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aws/aws-sdk-go-v2/aws"
	s3api "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/elgohr/go-localstack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"testing"

	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
)

type bucketDetails struct {
	bucketName          string
	acl                 string
	encrypted           bool
	loggingEnabled      bool
	loggingTargetBucket string
	versioningEnabled   bool
}

func Test_S3BucketACLs(t *testing.T) {

	tests := []struct {
		name        string
		initializer bucketDetails
		expected    bucketDetails
	}{
		{
			name: "simple bucket with public-acl acl",
			initializer: bucketDetails{
				bucketName: "test-bucket",
				acl:        "public-read",
				encrypted:  false,
			},
			expected: bucketDetails{
				bucketName: "test-bucket",
				acl:        "public-read",
				encrypted:  false,
			},
		},
		{
			name: "simple bucket with authenticated-read acl",
			initializer: bucketDetails{
				bucketName: "wide-open-bucket",
				acl:        "authenticated-read",
				encrypted:  false,
			},
			expected: bucketDetails{
				bucketName: "wide-open-bucket",
				acl:        "authenticated-read",
				encrypted:  false,
			},
		},
		{
			name: "simple bucket with public-read-write acl",
			initializer: bucketDetails{
				bucketName: "public-read-write-bucket",
				acl:        "public-read-write",
				encrypted:  false,
			},
			expected: bucketDetails{
				bucketName: "public-read-write-bucket",
				acl:        "public-read-write",
				encrypted:  false,
			},
		},
		{
			name: "simple bucket with private acl and encryption",
			initializer: bucketDetails{
				bucketName: "private-bucket",
				acl:        "private",
				encrypted:  true,
			},
			expected: bucketDetails{
				bucketName: "private-bucket",
				acl:        "private",
				encrypted:  true,
			},
		},
	}

	ra, err := test.CreateLocalstackAdapter(t, localstack.S3)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bootstrapBucket(t, ra, tt.initializer)

			testState := &state.State{}
			s3Adapter := &adapter{}
			err = s3Adapter.Adapt(ra, testState)
			require.NoError(t, err)

			assert.Len(t, testState.AWS.S3.Buckets, 1)
			got := testState.AWS.S3.Buckets[0]

			assert.Equal(t, tt.expected.bucketName, got.Name.Value())
			assert.Equal(t, tt.expected.acl, got.ACL.Value())
			assert.Equal(t, tt.expected.encrypted, got.Encryption.Enabled.Value())
			removeBucket(t, ra, tt.initializer)
		})
	}
}

func Test_S3BucketLogging(t *testing.T) {

	tests := []struct {
		name        string
		initializer bucketDetails
		expected    bucketDetails
	}{
		{
			name: "simple bucket with no logging enabled",
			initializer: bucketDetails{
				bucketName:     "test-bucket",
				acl:            "public-read",
				loggingEnabled: false,
			},
			expected: bucketDetails{
				bucketName:     "test-bucket",
				acl:            "public-read",
				loggingEnabled: false,
			},
		},
		{
			name: "simple bucket with logging enabled",
			initializer: bucketDetails{
				bucketName:          "test-bucket",
				acl:                 "public-read",
				loggingEnabled:      true,
				loggingTargetBucket: "access-logs",
			},
			expected: bucketDetails{
				bucketName:          "test-bucket",
				acl:                 "public-read",
				loggingEnabled:      true,
				loggingTargetBucket: "access-logs",
			},
		},
	}

	ra, err := test.CreateLocalstackAdapter(t, localstack.S3)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bootstrapBucket(t, ra, tt.initializer)

			testState := &state.State{}
			s3Adapter := &adapter{}
			err = s3Adapter.Adapt(ra, testState)
			require.NoError(t, err)

			assert.Len(t, testState.AWS.S3.Buckets, 2)
			var got s3.Bucket
			for _, b := range testState.AWS.S3.Buckets {
				if b.Name.Value() == tt.initializer.bucketName {
					got = b
					break
				}
			}

			assert.Equal(t, tt.expected.bucketName, got.Name.Value())
			if tt.expected.loggingEnabled {
				assert.Equal(t, tt.expected.loggingTargetBucket, got.Logging.TargetBucket.Value())
				assert.Equal(t, tt.expected.loggingEnabled, got.Logging.Enabled.Value())
			} else {
				assert.False(t, got.Logging.Enabled.Value())
			}
			removeBucket(t, ra, tt.initializer)
		})
	}
}

func bootstrapBucket(t *testing.T, ra *aws2.RootAdapter, spec bucketDetails) {

	api := s3api.NewFromConfig(ra.SessionConfig())

	_, err := api.CreateBucket(ra.Context(), &s3api.CreateBucketInput{
		Bucket: aws.String(spec.bucketName),

		ACL: aclToCannedACL(spec.acl),
	})
	require.NoError(t, err)

	if spec.encrypted {
		_, err = api.PutBucketEncryption(
			ra.Context(),
			&s3api.PutBucketEncryptionInput{
				Bucket: aws.String(spec.bucketName),
				ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
					Rules: []s3types.ServerSideEncryptionRule{
						{
							ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
								SSEAlgorithm: s3types.ServerSideEncryptionAes256,
							},
							BucketKeyEnabled: true,
						},
					},
				},
			})
		require.NoError(t, err)
	}

	if spec.loggingEnabled {

		_, err = api.PutBucketLogging(ra.Context(), &s3api.PutBucketLoggingInput{
			Bucket: aws.String(spec.bucketName),
			BucketLoggingStatus: &s3types.BucketLoggingStatus{
				LoggingEnabled: &s3types.LoggingEnabled{
					TargetBucket: aws.String(spec.loggingTargetBucket),
					TargetPrefix: aws.String("/logs"),
					TargetGrants: []s3types.TargetGrant{
						{
							Permission: s3types.BucketLogsPermissionWrite,
							Grantee: &s3types.Grantee{
								Type: s3types.TypeGroup,
								URI:  aws.String("http://acs.amazonaws.com/groups/s3/LogDelivery"),
							},
						},
					},
				},
			},
		})
		require.NoError(t, err)
	}

}

func aclToCannedACL(acl string) s3types.BucketCannedACL {
	switch acl {
	case "authenticated-read":
		return s3types.BucketCannedACLAuthenticatedRead
	case "public-read":
		return s3types.BucketCannedACLPublicRead
	case "public-read-write":
		return s3types.BucketCannedACLPublicReadWrite
	default:
		return s3types.BucketCannedACLPrivate
	}
}

func removeBucket(t *testing.T, ra *aws2.RootAdapter, spec bucketDetails) {

	api := s3api.NewFromConfig(ra.SessionConfig())

	_, err := api.DeleteBucket(ra.Context(), &s3api.DeleteBucketInput{
		Bucket: aws.String(spec.bucketName),
	})
	require.NoError(t, err)

	if spec.loggingEnabled && spec.loggingTargetBucket != "" {
		_, err := api.DeleteBucket(ra.Context(), &s3api.DeleteBucketInput{
			Bucket: aws.String(spec.loggingTargetBucket),
		})
		require.NoError(t, err)
	}

	require.NoError(t, err)
}
