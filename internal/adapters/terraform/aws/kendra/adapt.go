package kendra

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/kendra"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) kendra.Kendra {
	return kendra.Kendra{
		ListIndices: adaptListIndices(modules),
	}
}

func adaptListIndices(modules terraform.Modules) []kendra.ListIndices {
	var indices []kendra.ListIndices
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_kendra_index") {
			indices = append(indices, adaptIndex(resource))
		}
	}
	return indices
}

func adaptIndex(resource *terraform.Block) kendra.ListIndices {

	index := kendra.ListIndices{
		Metadata: resource.GetMetadata(),
		KmsKey: kendra.KmsKey{
			Metadata: resource.GetMetadata(),
			KmsKeyId: types.StringDefault("", resource.GetMetadata()),
		},
	}

	if serverSideEncryption := resource.GetBlock("server_side_encryption_configuration"); serverSideEncryption.IsNotNil() {
		index.KmsKey.Metadata = serverSideEncryption.GetMetadata()
		kmskeyAttr := serverSideEncryption.GetAttribute("kms_key_id")
		index.KmsKey.KmsKeyId = kmskeyAttr.AsStringValueOrDefault("", serverSideEncryption)
	}

	return index
}
