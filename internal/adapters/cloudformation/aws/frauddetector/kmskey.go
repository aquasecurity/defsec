package frauddetector

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/frauddetector"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getKmsKey(ctx parser.FileContext) frauddetector.KmsKey {

	deliveryDescriptions := frauddetector.KmsKey{
		Metadata:            types.NewUnmanagedMetadata(),
		KmsEncryptionKeyArn: types.StringDefault("", ctx.Metadata()),
	}

	deliveryDescriptionsResource := ctx.GetResourcesByType("AWS::FraudDetector::Detector")

	if len(deliveryDescriptionsResource) == 0 {
		return deliveryDescriptions
	}

	return frauddetector.KmsKey{
		Metadata:            deliveryDescriptionsResource[0].Metadata(),
		KmsEncryptionKeyArn: isKmsEncryptionKeyArn(deliveryDescriptionsResource[0]),
	}
}

func isKmsEncryptionKeyArn(r *parser.Resource) types.StringValue {
	kmsEncryptionKeyArnProp := types.StringUnresolvable(r.Metadata())

	return kmsEncryptionKeyArnProp
}
