package wisdom

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/wisdom"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/wisdom"
	"github.com/aws/aws-sdk-go-v2/service/wisdom/types"
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
	return "wisdom"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Wisdom.Assistants, err = a.getAssistants()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getAssistants() ([]wisdom.Assistant, error) {

	a.Tracker().SetServiceLabel("Discovering assistants...")

	var assistants []types.AssistantSummary
	var input api.ListAssistantsInput
	for {
		output, err := a.client.ListAssistants(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		assistants = append(assistants, output.AssistantSummaries...)
		a.Tracker().SetTotalResources(len(assistants))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting assistants...")
	return concurrency.Adapt(assistants, a.RootAdapter, a.adaptDomain), nil
}

func (a *adapter) adaptDomain(assistant types.AssistantSummary) (*wisdom.Assistant, error) {
	metadata := a.CreateMetadataFromARN(*assistant.AssistantArn)

	var key string

	if assistant.ServerSideEncryptionConfiguration != nil {
		key = *assistant.ServerSideEncryptionConfiguration.KmsKeyId
	}
	return &wisdom.Assistant{
		Metadata: metadata,
		KmsKeyId: defsecTypes.String(key, metadata),
	}, nil
}
