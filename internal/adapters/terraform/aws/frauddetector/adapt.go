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
	deliveryStreamDescription := frauddetector.KmsKey{
		Metadata:            types.NewUnmanagedMetadata(),
		KmsEncryptionKeyArn: types.StringDefault("", types.NewUnmanagedMetadata()),
	}

	for _, resource := range modules.GetResourcesByType("awscc_frauddetector_outcome") {
		deliveryStreamDescription.Metadata = resource.GetMetadata()
		deliveryStreamDescription.KmsEncryptionKeyArn = types.StringUnresolvable(resource.GetMetadata())
	}

	return deliveryStreamDescription
}
