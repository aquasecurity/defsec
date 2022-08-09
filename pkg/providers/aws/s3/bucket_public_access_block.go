package s3

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type PublicAccessBlock struct {
	types2.Metadata
	BlockPublicACLs       types2.BoolValue
	BlockPublicPolicy     types2.BoolValue
	IgnorePublicACLs      types2.BoolValue
	RestrictPublicBuckets types2.BoolValue
}

func NewPublicAccessBlock(metadata types2.Metadata) PublicAccessBlock {
	return PublicAccessBlock{
		Metadata:              metadata,
		BlockPublicPolicy:     types2.BoolDefault(false, metadata),
		BlockPublicACLs:       types2.BoolDefault(false, metadata),
		IgnorePublicACLs:      types2.BoolDefault(false, metadata),
		RestrictPublicBuckets: types2.BoolDefault(false, metadata),
	}
}
