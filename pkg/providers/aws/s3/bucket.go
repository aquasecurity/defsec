package s3

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Bucket struct {
	Metadata                defsecTypes.Metadata
	Name                    defsecTypes.StringValue
	PublicAccessBlock       *PublicAccessBlock
	BucketPolicies          []iam.Policy
	Encryption              Encryption
	Versioning              Versioning
	Logging                 Logging
	ACL                     defsecTypes.StringValue
	ObjectLockConfiguration ObjectLockConfiguration
}

func (b *Bucket) HasPublicExposureACL() bool {
	for _, publicACL := range []string{"public-read", "public-read-write", "website", "authenticated-read"} {
		if b.ACL.EqualTo(publicACL) {
			// if there is a public access block, check the public ACL blocks
			if b.PublicAccessBlock != nil && b.PublicAccessBlock.Metadata.IsManaged() {
				return b.PublicAccessBlock.IgnorePublicACLs.IsFalse() && b.PublicAccessBlock.BlockPublicACLs.IsFalse()
			}
			return true
		}
	}
	return false
}

type Logging struct {
	Metadata     defsecTypes.Metadata
	Enabled      defsecTypes.BoolValue
	TargetBucket defsecTypes.StringValue
}

type Versioning struct {
	Metadata  defsecTypes.Metadata
	Enabled   defsecTypes.BoolValue
	MFADelete defsecTypes.BoolValue
}

type Encryption struct {
	Metadata  defsecTypes.Metadata
	Enabled   defsecTypes.BoolValue
	Algorithm defsecTypes.StringValue
	KMSKeyId  defsecTypes.StringValue
}

type DefaultRetention struct {
	Mode  defsecTypes.StringValue
	Days  defsecTypes.IntValue
	Years defsecTypes.IntValue
	Token defsecTypes.StringValue
}

type ObjectLockConfiguration struct {
	Metadata         defsecTypes.Metadata
	Enabled          defsecTypes.BoolValue
	DefaultRetention DefaultRetention
}
