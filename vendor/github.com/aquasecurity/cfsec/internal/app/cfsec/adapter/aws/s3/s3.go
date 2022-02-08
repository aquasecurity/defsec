package s3

import (
	"reflect"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/s3"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result s3.S3) {
	defer func() {
		if r := recover(); r != nil {
			metadata := cfFile.Metadata()
			debug.Log("There were errors adapting %s from %s", reflect.TypeOf(result), metadata.Range().GetFilename())
		}
	}()

	result.Buckets = getBuckets(cfFile)
	result.PublicAccessBlocks = getPublicAccessBlocks(result.Buckets)
	return result
}

func getPublicAccessBlocks(buckets []s3.Bucket) (publicAccessBlocks []s3.PublicAccessBlock) {
	for _, b := range buckets {
		if b.PublicAccessBlock != nil {
			publicAccessBlocks = append(publicAccessBlocks, *b.PublicAccessBlock)
		}
	}
	return publicAccessBlocks
}
