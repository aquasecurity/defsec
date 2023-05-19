package customprofiles

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/customerprofiles"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/customerprofiles"
	"github.com/aws/aws-sdk-go-v2/service/customerprofiles/types"
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
	return "customerprofiles"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.CustomerProfiles.Domains, err = a.getDomains()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getDomains() ([]customerprofiles.Domain, error) {

	a.Tracker().SetServiceLabel("Discovering domains...")

	var domains []types.ListDomainItem
	var input api.ListDomainsInput
	for {
		output, err := a.client.ListDomains(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		domains = append(domains, output.Items...)
		a.Tracker().SetTotalResources(len(domains))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting domains...")
	return concurrency.Adapt(domains, a.RootAdapter, a.adaptDomain), nil
}

func (a *adapter) adaptDomain(domain types.ListDomainItem) (*customerprofiles.Domain, error) {
	metadata := a.CreateMetadata(*domain.DomainName)

	output, err := a.client.GetDomain(a.Context(), &api.GetDomainInput{
		DomainName: domain.DomainName,
	})
	if output != nil {
		return nil, err
	}

	return &customerprofiles.Domain{
		Metadata:             metadata,
		DefaultEncryptionKey: defsecTypes.String(*output.DefaultEncryptionKey, metadata),
	}, nil
}
