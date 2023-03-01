package frauddetector

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/frauddetector"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) frauddetector.Frauddetector {
	return frauddetector.Frauddetector{
		KmsKey: adaptKmskey(modules),
	}
}

func adaptKmskey(modules terraform.Modules) frauddetector.KmsKey {
	var DeliveryStreamDescription frauddetector.KmsKey
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("awscc_frauddetector_outcome") {
			DeliveryStreamDescription = adaptKmsKey(resource, module)
		}
	}
	return DeliveryStreamDescription
}

func adaptKmsKey(resource *terraform.Block, module *terraform.Module) frauddetector.KmsKey {
	var KeyVal string

	return frauddetector.KmsKey{
		Metadata:            resource.GetMetadata(),
		KmsEncryptionKeyArn: types.String(KeyVal, types.Metadata{}),
	}
}
