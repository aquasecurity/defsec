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
	state.AWS.Organizations.Organization, err = a.getOrganization()
	if err != nil {
		return err
	}

	state.AWS.Organizations.AccountHandshakes, err = a.getHandShakes()
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
	return concurrency.Adapt(apiAccounts, a.RootAdapter, a.adaptAccount), nil
}

func (a *adapter) adaptAccount(account types.Account) (*organizations.Account, error) {
	metadata := a.CreateMetadataFromARN(*account.Arn)

	return &organizations.Account{
		Metadata: metadata,
		Id:       defsecTypes.String(*account.Id, metadata),
	}, nil
}

func (a *adapter) getOrganization() (organizations.Organization, error) {

	a.Tracker().SetServiceLabel("Discovering organizations..")

	var input api.DescribeOrganizationInput

	organization := organizations.Organization{
		Metadata:   defsecTypes.NewUnmanagedMetadata(),
		FeatureSet: defsecTypes.String("", defsecTypes.NewUnmanagedMetadata()),
	}

	output, err := a.api.DescribeOrganization(a.Context(), &input)
	if err != nil {
		return organization, err
	}
	if err != nil {
		metadata := a.CreateMetadataFromARN(*output.Organization.Arn)
		organization.Metadata = metadata
		organization.FeatureSet = defsecTypes.String(string(output.Organization.FeatureSet), metadata)
	}

	return organization, nil

}

func (a *adapter) getHandShakes() ([]organizations.AccountHandshake, error) {

	a.Tracker().SetServiceLabel("Discovering account handshakes..")

	var input api.ListHandshakesForAccountInput
	var apiHandshakes []types.Handshake
	for {
		output, err := a.api.ListHandshakesForAccount(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiHandshakes = append(apiHandshakes, output.Handshakes...)
		a.Tracker().SetTotalResources(len(apiHandshakes))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting account handshake...")
	return concurrency.Adapt(apiHandshakes, a.RootAdapter, a.adaptHandshake), nil
}

func (a *adapter) adaptHandshake(handshake types.Handshake) (*organizations.AccountHandshake, error) {
	metadata := a.CreateMetadataFromARN(*handshake.Arn)

	return &organizations.AccountHandshake{
		Metadata: metadata,
		State:    defsecTypes.String(string(handshake.State), metadata),
		Action:   defsecTypes.String(string(handshake.Action), metadata),
	}, nil
}
