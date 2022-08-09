package s3

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Bucket struct {
	types2.Metadata
	Name              types2.StringValue
	PublicAccessBlock *PublicAccessBlock
	BucketPolicies    []iam.Policy
	Encryption        Encryption
	Versioning        Versioning
	Logging           Logging
	ACL               types2.StringValue
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
	types2.Metadata
	Enabled      types2.BoolValue
	TargetBucket types2.StringValue
}

type Versioning struct {
	types2.Metadata
	Enabled types2.BoolValue
}

type Encryption struct {
	types2.Metadata
	Enabled   types2.BoolValue
	Algorithm types2.StringValue
	KMSKeyId  types2.StringValue
}
