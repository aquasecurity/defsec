package kinesis

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/kinesis"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/kinesis"
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
	return "kinesis"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Kinesis.Streams, err = a.getStreams()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getStreams() ([]kinesis.Stream, error) {

	a.Tracker().SetServiceLabel("Discovering streams...")

	var apiStreams []string
	var input api.ListStreamsInput
	for {
		output, err := a.api.ListStreams(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiStreams = append(apiStreams, output.StreamNames...)
		a.Tracker().SetTotalResources(len(apiStreams))
		if output.HasMoreStreams == nil || !*output.HasMoreStreams {
			break
		}
		input.ExclusiveStartStreamName = &output.StreamNames[len(output.StreamNames)-1]
	}

	a.Tracker().SetServiceLabel("Adapting streams...")

	var streams []kinesis.Stream
	var lastName string
	for _, apiStream := range apiStreams {
		if lastName != apiStream {
			stream, err := a.adaptStream(apiStream)
			if err != nil {
				a.Debug("Failed to adapt stream '%s': %s", apiStream, err)
				continue
			}
			streams = append(streams, *stream)
		}
		lastName = apiStream
		a.Tracker().IncrementResource()
	}

	return streams, nil
}

func (a *adapter) adaptStream(streamName string) (*kinesis.Stream, error) {

	output, err := a.api.DescribeStream(a.Context(), &api.DescribeStreamInput{
		StreamName:            &streamName,
		ExclusiveStartShardId: nil,
		Limit:                 nil,
	})
	if err != nil {
		return nil, err
	}

	metadata := a.CreateMetadataFromARN(*output.StreamDescription.StreamARN)

	var kmsKeyId string
	if output.StreamDescription.KeyId != nil {
		kmsKeyId = *output.StreamDescription.KeyId
	}

	return &kinesis.Stream{
		Metadata: metadata,
		Encryption: kinesis.Encryption{
			Metadata: metadata,
			Type:     defsecTypes.String(string(output.StreamDescription.EncryptionType), metadata),
			KMSKeyID: defsecTypes.String(kmsKeyId, metadata),
		},
	}, nil

}
