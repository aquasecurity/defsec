package timestreamwrite

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/timestreamwrite"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/timestreamwrite"
	aatypes "github.com/aws/aws-sdk-go-v2/service/timestreamwrite/types"
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
	return "timestreamwrite"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Timestreamwrite.ListDatabases, err = a.getDatabases()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getDatabases() ([]timestreamwrite.Databases, error) {

	a.Tracker().SetServiceLabel("Discovering listed Databases...")

	var apiListDatabases []aatypes.Database
	var input api.ListDatabasesInput
	for {
		output, err := a.api.ListDatabases(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiListDatabases = append(apiListDatabases, output.Databases...)
		a.Tracker().SetTotalResources(len(apiListDatabases))
		if output.Databases == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting listed databases...")
	return concurrency.Adapt(apiListDatabases, a.RootAdapter, a.adaptListDatabases), nil
}

func (a *adapter) adaptListDatabases(apiListServer aatypes.Database) (*timestreamwrite.Databases, error) {

	metadata := a.CreateMetadataFromARN(*apiListServer.Arn)

	var arn string
	if apiListServer.Arn != nil {
		arn = *apiListServer.Arn
	}

	var keyid string
	if apiListServer.KmsKeyId != nil {
		keyid = *apiListServer.KmsKeyId
	}

	return &timestreamwrite.Databases{
		Metadata: metadata,
		Arn:      defsecTypes.String(arn, metadata),
		KmsKeyID: defsecTypes.String(keyid, metadata),
	}, nil
}
