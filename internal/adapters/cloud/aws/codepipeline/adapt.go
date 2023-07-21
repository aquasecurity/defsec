package codepipeline

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/codepipeline"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/codepipeline"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
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
	return "codepipeline"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.CodePipeline.Pipelines, err = a.getPipelines()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getPipelines() ([]codepipeline.Pipeline, error) {

	a.Tracker().SetServiceLabel("Discovering pipelines..")

	var apipipelines []types.PipelineSummary
	var input api.ListPipelinesInput
	for {
		output, err := a.client.ListPipelines(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apipipelines = append(apipipelines, output.Pipelines...)
		a.Tracker().SetTotalResources(len(apipipelines))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting pipelines...")
	return concurrency.Adapt(apipipelines, a.RootAdapter, a.adaptPipeline), nil
}

func (a *adapter) adaptPipeline(pipeline types.PipelineSummary) (*codepipeline.Pipeline, error) {
	metadata := a.CreateMetadata(*pipeline.Name)

	output, err := a.client.GetPipeline(a.Context(), &api.GetPipelineInput{
		Name: pipeline.Name,
	})
	if err != nil {
		return nil, err
	}

	var key string
	if output.Pipeline.ArtifactStore != nil && output.Pipeline.ArtifactStore.EncryptionKey != nil {
		key = *output.Pipeline.ArtifactStore.EncryptionKey.Id
	}

	return &codepipeline.Pipeline{
		Metadata:      metadata,
		EncryptionKey: defsecTypes.String(key, metadata),
	}, nil
}
