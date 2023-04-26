package kendra

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/kendra"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getListIndices(ctx parser.FileContext) (indices []kendra.ListIndices) {

	indexResources := ctx.GetResourcesByType("AWS::Kendra::Index")

	for _, r := range indexResources {
		indexkey := kendra.ListIndices{
			Metadata: r.Metadata(),
			KmsKey: kendra.KmsKey{
				Metadata: r.Metadata(),
				KmsKeyId: r.GetStringProperty("ServerSideEncryptionConfiguration.KmsKeyId"),
			},
		}

		indices = append(indices, indexkey)
	}

	return indices
}
