package ecr

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elastictranscoder"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/elastictranscoder"
	"github.com/aws/aws-sdk-go-v2/service/elastictranscoder/types"
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
	return "elastictranscoder"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Elastictranscoder.Pipelines, err = a.getPipelines()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getPipelines() ([]elastictranscoder.Pipeline, error) {

	a.Tracker().SetServiceLabel("Discovering pipelines..")

	var input api.ListPipelinesInput

	var apiPipelines []types.Pipeline
	for {
		output, err := a.api.ListPipelines(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiPipelines = append(apiPipelines, output.Pipelines...)
		a.Tracker().SetTotalResources(len(apiPipelines))
		if output.NextPageToken == nil {
			break
		}
		input.PageToken = output.NextPageToken
	}

	a.Tracker().SetServiceLabel("Adapting repositories...")
	return concurrency.Adapt(apiPipelines, a.RootAdapter, a.adaptPipeline), nil
}

func (a *adapter) adaptPipeline(pipeline types.Pipeline) (*elastictranscoder.Pipeline, error) {
	metadata := a.CreateMetadataFromARN(*pipeline.Arn)

	output, err := a.api.ListJobsByPipeline(a.Context(), &api.ListJobsByPipelineInput{
		PipelineId: pipeline.Id,
	})
	if err != nil {
		return nil, err
	}

	var status string
	var outputs []elastictranscoder.Output
	for _, p := range output.Jobs {
		status = *p.Status

		for _, o := range p.Outputs {

			var key string
			if o.Encryption != nil {
				key = *o.Encryption.Key
			}
			outputs = append(outputs, elastictranscoder.Output{
				Metadata: metadata,
				Encryption: elastictranscoder.Encryption{
					Metadata: metadata,
					Key:      defsecTypes.String(key, metadata),
				},
			})
		}
	}

	return &elastictranscoder.Pipeline{
		Metadata:     metadata,
		AwsKmsKeyArn: defsecTypes.String(*pipeline.AwsKmsKeyArn, metadata),
		Status:       defsecTypes.String(status, metadata),
		Outputs:      outputs,
	}, nil
}
