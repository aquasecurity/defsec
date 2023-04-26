package firehose

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/firehose"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func getDeliveryStreamDescription(ctx parser.FileContext) firehose.DeliveryStreamDescription {

	deliveryDescriptions := firehose.DeliveryStreamDescription{
		Metadata:     defsecTypes.NewUnmanagedMetadata(),
		AWSKMSKeyARN: defsecTypes.StringDefault("", ctx.Metadata()),
	}

	deliveryStreamDescriptionResource := ctx.GetResourcesByType("AWS::KinesisFirehose::DeliveryStream")

	if len(deliveryStreamDescriptionResource) == 0 {
		return deliveryDescriptions
	}

	return firehose.DeliveryStreamDescription{
		Metadata:     deliveryStreamDescriptionResource[0].Metadata(),
		AWSKMSKeyARN: isAwsKmsKeyArn(deliveryStreamDescriptionResource[0]),
	}
}

func isAwsKmsKeyArn(r *parser.Resource) defsecTypes.StringValue {
	kmsKeyArnProp := r.GetProperty("KMSEncryptionConfig")

	if kmsKeyArnProp.IsNotNil() {
		return kmsKeyArnProp.AsStringValue()
	}

	return defsecTypes.StringDefault("", r.Metadata())
}
