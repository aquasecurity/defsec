package transfer

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/transfer"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/transfer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"
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
	return "transfer"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Transfer.ListServers, err = a.getListServers()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getListServers() ([]transfer.Servers, error) {

	a.Tracker().SetServiceLabel("Discovering listed servers...")

	var apiListServer []aatypes.ListedServer
	var input api.ListServersInput
	for {
		output, err := a.api.ListServers(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiListServer = append(apiListServer, output.Servers...)
		a.Tracker().SetTotalResources(len(apiListServer))
		if output.Servers == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting listed servers...")
	return concurrency.Adapt(apiListServer, a.RootAdapter, a.adaptListServers), nil
}

func (a *adapter) adaptListServers(apiListServer aatypes.ListedServer) (*transfer.Servers, error) {

	metadata := a.CreateMetadataFromARN(*apiListServer.Arn)

	var arn string
	if apiListServer.Arn != nil {
		arn = *apiListServer.Arn
	}

	return &transfer.Servers{
		Metadata:  metadata,
		ServerArn: defsecTypes.String(arn, metadata),
	}, nil
}
