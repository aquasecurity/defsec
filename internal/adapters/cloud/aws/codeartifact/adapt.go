package cloudformation

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/codeartifact"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/codeartifact"
	"github.com/aws/aws-sdk-go-v2/service/codeartifact/types"
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
	return "codeartifact"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.CodeArtifact.Domains, err = a.getDomains()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getDomains() ([]codeartifact.Domain, error) {

	a.Tracker().SetServiceLabel("Discovering domains...")

	var apidomains []types.DomainSummary
	var input api.ListDomainsInput
	for {
		output, err := a.client.ListDomains(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apidomains = append(apidomains, output.Domains...)
		a.Tracker().SetTotalResources(len(apidomains))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting domains...")
	return concurrency.Adapt(apidomains, a.RootAdapter, a.adaptDomain), nil
}

func (a *adapter) adaptDomain(domain types.DomainSummary) (*codeartifact.Domain, error) {
	metadata := a.CreateMetadataFromARN(*domain.Arn)
	return &codeartifact.Domain{
		Metadata:      metadata,
		Arn:           defsecTypes.String(*domain.Arn, metadata),
		EncryptionKey: defsecTypes.String(*domain.EncryptionKey, metadata),
	}, nil
}
