package firehose

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Firehose struct {
	DescribeStream DeliveryStreamDescription
}

type DeliveryStreamDescription struct {
	Metadata     defsecTypes.Metadata
	AWSKMSKeyARN defsecTypes.StringValue
}
