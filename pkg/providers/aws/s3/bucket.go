package s3

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Bucket struct {
	defsecTypes.Metadata
	Name              defsecTypes.StringValue
	PublicAccessBlock *PublicAccessBlock
	BucketPolicies    []iam.Policy
	Encryption        Encryption
	Versioning        Versioning
	Logging           Logging
	ACL               defsecTypes.StringValue
}

func (b *Bucket) HasPublicExposureACL() bool {
	for _, publicACL := range []string{"public-read", "public-read-write", "website", "authenticated-read"} {
		if b.ACL.EqualTo(publicACL) {
			// if there is a public access block, check the public ACL blocks
			if b.PublicAccessBlock != nil && b.PublicAccessBlock.IsManaged() {
				return b.PublicAccessBlock.IgnorePublicACLs.IsFalse() && b.PublicAccessBlock.BlockPublicACLs.IsFalse()
			}
			return true
		}
	}
	return false
}

type Logging struct {
	defsecTypes.Metadata
	Enabled      defsecTypes.BoolValue
	TargetBucket defsecTypes.StringValue
}

type Versioning struct {
	defsecTypes.Metadata
	Enabled   defsecTypes.BoolValue
	MFADelete defsecTypes.BoolValue
}

type Encryption struct {
	defsecTypes.Metadata
	Enabled   defsecTypes.BoolValue
	Algorithm defsecTypes.StringValue
	KMSKeyId  defsecTypes.StringValue
}
