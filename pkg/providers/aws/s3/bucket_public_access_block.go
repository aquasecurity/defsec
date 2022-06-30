package s3

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type PublicAccessBlock struct {
	types.Metadata
	BlockPublicACLs       types.BoolValue
	BlockPublicPolicy     types.BoolValue
	IgnorePublicACLs      types.BoolValue
	RestrictPublicBuckets types.BoolValue
}

func NewPublicAccessBlock(metadata types.Metadata) PublicAccessBlock {
	return PublicAccessBlock{
		Metadata:              metadata,
		BlockPublicPolicy:     types.BoolDefault(false, metadata),
		BlockPublicACLs:       types.BoolDefault(false, metadata),
		IgnorePublicACLs:      types.BoolDefault(false, metadata),
		RestrictPublicBuckets: types.BoolDefault(false, metadata),
	}
}
