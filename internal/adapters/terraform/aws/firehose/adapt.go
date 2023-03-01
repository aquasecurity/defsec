package firehose

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/firehose"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) firehose.Firehose {
	return firehose.Firehose{
		DescribeStream: adaptDescribeStream(modules),
	}
}

func adaptDescribeStream(modules terraform.Modules) firehose.DeliveryStreamDescription {
	var DeliveryStreamDescription firehose.DeliveryStreamDescription
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_kinesis_firehose_delivery_stream") {
			DeliveryStreamDescription = adaptKmsKey(resource, module)
		}
	}
	return DeliveryStreamDescription
}

func adaptKmsKey(resource *terraform.Block, module *terraform.Module) firehose.DeliveryStreamDescription {
	keyAttr := resource.GetAttribute("kms_key_arn")
	keyVal := keyAttr.AsStringValueOrDefault("", resource)

	return firehose.DeliveryStreamDescription{
		Metadata:     resource.GetMetadata(),
		AWSKMSKeyARN: keyVal,
	}
}
