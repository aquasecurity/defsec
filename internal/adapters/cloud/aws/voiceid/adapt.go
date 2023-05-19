package voiceid

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	voiceid "github.com/aquasecurity/defsec/pkg/providers/aws/voiceId"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/voiceid"
	"github.com/aws/aws-sdk-go-v2/service/voiceid/types"
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
	return "voiceid"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.VoiceId.Domains, err = a.getDomains()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getDomains() ([]voiceid.Domain, error) {

	a.Tracker().SetServiceLabel("Discovering domains...")

	var domains []types.DomainSummary
	var input api.ListDomainsInput
	for {
		output, err := a.client.ListDomains(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		domains = append(domains, output.DomainSummaries...)
		a.Tracker().SetTotalResources(len(domains))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting domains...")
	return concurrency.Adapt(domains, a.RootAdapter, a.adaptDomain), nil
}

func (a *adapter) adaptDomain(domain types.DomainSummary) (*voiceid.Domain, error) {
	metadata := a.CreateMetadataFromARN(*domain.Arn)

	var key string
	if domain.ServerSideEncryptionConfiguration != nil {
		key = *domain.ServerSideEncryptionConfiguration.KmsKeyId
	}

	return &voiceid.Domain{
		Metadata: metadata,
		KmsKeyId: defsecTypes.String(key, metadata),
	}, nil
}
