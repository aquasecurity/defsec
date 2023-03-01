package finspace

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/finspace"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/finspace"
	aatypes "github.com/aws/aws-sdk-go-v2/service/finspace/types"
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
	return "finspace"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Finspace.Environments, err = a.getListEnvironments()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getListEnvironments() ([]finspace.Environment, error) {

	a.Tracker().SetServiceLabel("Discovering finspace Environement...")

	var apiEnvironement []aatypes.Environment
	var input api.ListEnvironmentsInput
	for {
		output, err := a.api.ListEnvironments(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiEnvironement = append(apiEnvironement, output.Environments...)
		a.Tracker().SetTotalResources(len(apiEnvironement))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting finspace environments...")
	return concurrency.Adapt(apiEnvironement, a.RootAdapter, a.adaptListEnvironment), nil
}

func (a *adapter) adaptListEnvironment(apiEnvironement aatypes.Environment) (*finspace.Environment, error) {

	metadata := a.CreateMetadataFromARN(*apiEnvironement.EnvironmentArn)

	return &finspace.Environment{
		Metadata:       metadata,
		EnvironmentArn: defsecTypes.String(*apiEnvironement.EnvironmentArn, metadata),
		KmsKeyId:       defsecTypes.String(*apiEnvironement.KmsKeyId, metadata),
	}, nil
}
