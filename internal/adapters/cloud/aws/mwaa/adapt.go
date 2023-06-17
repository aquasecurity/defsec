package mwaa

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/mwaa"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/mwaa"
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
	return "mwaa"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.MWAA.Environments, err = a.getEnvironments()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getEnvironments() ([]mwaa.Environmnet, error) {

	a.Tracker().SetServiceLabel("Discovering environments...")

	var apiEnvironments []string
	var input api.ListEnvironmentsInput

	for {
		output, err := a.api.ListEnvironments(a.Context(), &input)
		if err != nil {
			return nil, err
		}

		apiEnvironments = append(apiEnvironments, output.Environments...)
		a.Tracker().SetTotalResources(len(apiEnvironments))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting environment...")
	return concurrency.Adapt(apiEnvironments, a.RootAdapter, a.adaptEnvironment), nil
}

func (a *adapter) adaptEnvironment(environmnet string) (*mwaa.Environmnet, error) {

	output, err := a.api.GetEnvironment(a.Context(), &api.GetEnvironmentInput{
		Name: &environmnet,
	})
	if err != nil {
		return nil, err
	}
	metadata := a.CreateMetadataFromARN(*output.Environment.Arn)
	return &mwaa.Environmnet{
		Metadata:            metadata,
		ExecutionRoleArn:    defsecTypes.String(*output.Environment.ExecutionRoleArn, metadata),
		KmsKey:              defsecTypes.String(*output.Environment.KmsKey, metadata),
		WebserverAccessMode: defsecTypes.String(string(output.Environment.WebserverAccessMode), metadata),
	}, nil
}
