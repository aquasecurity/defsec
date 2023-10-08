package kms

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/kms"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getKeys(ctx parser.FileContext) (keys []kms.Key) {

	keyResources := ctx.GetResourcesByType("AWS::KMS::Key")

	for _, r := range keyResources {

		key := kms.Key{
			Metadata: r.Metadata(),
			Manager:  types.StringDefault("AWS", r.Metadata()),
		}
		
		keys = append(keys, key)
	}

	return keys
}

