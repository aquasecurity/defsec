package kinesisvideo

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/kinesisvideo"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/kinesisvideo"
	aatypes "github.com/aws/aws-sdk-go-v2/service/kinesisvideo/types"
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
	return "kinesisvideo"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Kinesisvideo.StreamInfoList, err = a.getStreamInfo()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getStreamInfo() ([]kinesisvideo.StreamInfo, error) {

	a.Tracker().SetServiceLabel("Discovering Stram Info...")

	var apiStreamInfo []aatypes.StreamInfo
	var input api.ListStreamsInput
	for {
		output, err := a.api.ListStreams(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiStreamInfo = append(apiStreamInfo, output.StreamInfoList...)
		a.Tracker().SetTotalResources(len(apiStreamInfo))
		if output.StreamInfoList == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting Stream Info...")
	return concurrency.Adapt(apiStreamInfo, a.RootAdapter, a.adaptStreamInfo), nil
}

func (a *adapter) adaptStreamInfo(apiStreamInfo aatypes.StreamInfo) (*kinesisvideo.StreamInfo, error) {

	metadata := a.CreateMetadataFromARN(*apiStreamInfo.StreamARN)

	var key string
	if apiStreamInfo.KmsKeyId != nil {
		key = *apiStreamInfo.KmsKeyId
	}

	return &kinesisvideo.StreamInfo{
		Metadata: metadata,
		KmsKeyId: defsecTypes.String(key, metadata),
	}, nil
}
