package s3

import "github.com/aquasecurity/defsec/types"

type S3 struct {
	types.Metadata
	Buckets            []Bucket
	PublicAccessBlocks []PublicAccessBlock
}
