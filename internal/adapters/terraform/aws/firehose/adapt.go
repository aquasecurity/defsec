package firehose

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/firehose"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) firehose.Firehose {
	return firehose.Firehose{
		DescribeStream: adaptDescribeStream(modules),
	}
}

func adaptDescribeStream(modules terraform.Modules) firehose.DeliveryStreamDescription {
	deliveryStreamDescription := firehose.DeliveryStreamDescription{
		Metadata:     defsecTypes.NewUnmanagedMetadata(),
		AWSKMSKeyARN: defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
	}

	for _, resource := range modules.GetResourcesByType("aws_kinesis_firehose_delivery_stream") {
		deliveryStreamDescription.Metadata = resource.GetMetadata()
		deliveryStreamDescription.AWSKMSKeyARN = resource.GetAttribute("kms_key_arn").AsStringValueOrDefault("", resource)
	}

	return deliveryStreamDescription
}
