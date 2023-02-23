package organizations

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/organizations"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
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
	return "organizations"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Organizations.Accounts, err = a.getAccounts()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getAccounts() ([]organizations.Account, error) {

	a.Tracker().SetServiceLabel("Discovering accounts..")

	var input api.ListAccountsInput
	var apiAccounts []types.Account
	for {
		output, err := a.api.ListAccounts(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiAccounts = append(apiAccounts, output.Accounts...)
		a.Tracker().SetTotalResources(len(apiAccounts))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting accounts...")
	return concurrency.Adapt(apiAccounts, a.RootAdapter, a.adaptEnvironment), nil
}

func (a *adapter) adaptEnvironment(account types.Account) (*organizations.Account, error) {
	metadata := a.CreateMetadataFromARN(*account.Arn)

	return &organizations.Account{
		Metadata: metadata,
		Id:       defsecTypes.String(*account.Id, metadata),
	}, nil
}
