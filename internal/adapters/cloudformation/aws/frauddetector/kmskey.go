package frauddetector

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/frauddetector"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getKmsKey(ctx parser.FileContext) (kmskeyarn frauddetector.KmsKey) {

	getDeliveryStreamDescription := ctx.GetResourcesByType("AWS::FraudDetector::Detector")

	for _, r := range getDeliveryStreamDescription {

		var Kmskey types.StringValue

		ds := frauddetector.KmsKey{
			Metadata:            r.Metadata(),
			KmsEncryptionKeyArn: Kmskey,
		}
		kmskeyarn = ds
	}

	return kmskeyarn
}
