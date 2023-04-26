package firehose

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/firehose"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/firehose"
	aatypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "firehose"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Firehose.DescribeStream, err = a.getDeliveryStream()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getDeliveryStream() (firehose.DeliveryStreamDescription, error) {
	var apiDeliveryStream aatypes.DeliveryStreamDescription
	var input api.DescribeDeliveryStreamInput

	a.Tracker().SetServiceLabel("Discovering delivery streams descr...")
	metadata := a.CreateMetadataFromARN(*apiDeliveryStream.DeliveryStreamARN)

	var keyArn string
	for _, ka := range apiDeliveryStream.Destinations {
		var awskmskeyarn string
		if ka.ExtendedS3DestinationDescription.EncryptionConfiguration.KMSEncryptionConfig.AWSKMSKeyARN != nil {
			awskmskeyarn = *ka.ExtendedS3DestinationDescription.EncryptionConfiguration.KMSEncryptionConfig.AWSKMSKeyARN
		}
		keyArn = awskmskeyarn
	}

	description := firehose.DeliveryStreamDescription{
		Metadata:     metadata,
		AWSKMSKeyARN: defsecTypes.String(keyArn, metadata),
	}

	output, err := a.api.DescribeDeliveryStream(a.Context(), &input)
	if err != nil {
		return description, err
	}

	apiDeliveryStream = *output.DeliveryStreamDescription

	return description, nil
}
