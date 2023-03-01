package firehose

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/firehose"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getDeliveryStreamDescription(ctx parser.FileContext) (kmskeyarn firehose.DeliveryStreamDescription) {

	getDeliveryStreamDescription := ctx.GetResourcesByType("AWS::KinesisFirehose::DeliveryStream")

	for _, r := range getDeliveryStreamDescription {

		var AWSKMSKeyARN types.StringValue
		keyarn := r.GetProperty("KMSEncryptionConfig").AsString()
		AWSKMSKeyARN = types.String(keyarn, types.Metadata{})

		ds := firehose.DeliveryStreamDescription{
			Metadata:     r.Metadata(),
			AWSKMSKeyARN: AWSKMSKeyARN,
		}
		kmskeyarn = ds
	}

	return kmskeyarn
}
