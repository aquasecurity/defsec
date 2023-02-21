package devopsguru

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/devopsguru"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/devopsguru"
	types "github.com/aws/aws-sdk-go-v2/service/devopsguru/types"
)

type adapter struct {
	*aws.RootAdapter
	client *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "devopsguru"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Devopsguru.NotificationChannels, err = a.getChannels()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getChannels() ([]devopsguru.NotificationChannel, error) {

	a.Tracker().SetServiceLabel("Discovering channels...")

	var channels []types.NotificationChannel
	var input api.ListNotificationChannelsInput
	for {
		output, err := a.client.ListNotificationChannels(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		channels = append(channels, output.Channels...)
		a.Tracker().SetTotalResources(len(channels))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting channels...")
	return concurrency.Adapt(channels, a.RootAdapter, a.adaptChannel), nil
}

func (a *adapter) adaptChannel(channel types.NotificationChannel) (*devopsguru.NotificationChannel, error) {
	metadata := a.CreateMetadata(*channel.Id)

	return &devopsguru.NotificationChannel{
		Metadata: metadata,
	}, nil
}
