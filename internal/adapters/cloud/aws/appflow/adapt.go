package appflow

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/appflow"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/appflow"
	aatypes "github.com/aws/aws-sdk-go-v2/service/appflow/types"
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
	return "appflow"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {
	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())

	var err error
	state.AWS.Appflow.ListFlows, err = a.getAppflow()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getAppflow() ([]appflow.ListFlow, error) {
	a.Tracker().SetServiceLabel(" Appflow list...")

	var input api.ListFlowsInput
	var appflowapi []aatypes.FlowDefinition

	for {
		output, err := a.api.ListFlows(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		appflowapi = append(appflowapi, output.Flows...)

		a.Tracker().SetTotalResources(len(appflowapi))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken

	}
	a.Tracker().SetServiceLabel("Adapting listflow...")
	return concurrency.Adapt(appflowapi, a.RootAdapter, a.adaptapplistflow), nil

}

func (a *adapter) adaptapplistflow(appflowapi aatypes.FlowDefinition) (*appflow.ListFlow, error) {

	metadata := a.CreateMetadataFromARN(*appflowapi.FlowArn)
	var name string
	if appflowapi.FlowName != nil {
		name = *appflowapi.FlowName
	}

	var arn string
	if appflowapi.FlowArn != nil {
		arn = *appflowapi.FlowArn
	}

	output, err := a.api.DescribeFlow(a.Context(), &api.DescribeFlowInput{
		FlowName: appflowapi.FlowName,
	})
	if err != nil {
		return nil, err
	}

	return &appflow.ListFlow{
		Metadata: metadata,
		FlowName: types.String(name, metadata),
		FlowArn:  types.String(arn, metadata),
		KMSArn:   types.String(*output.KmsArn, metadata),
	}, nil

}
