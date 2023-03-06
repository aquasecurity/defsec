package sagemaker

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sagemaker"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
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
	return "sagemaker"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.SageMaker.NotebookInstances, err = a.getInstances()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getInstances() ([]sagemaker.NotebookInstance, error) {

	a.Tracker().SetServiceLabel("Discovering instances...")

	var apiinstances []types.NotebookInstanceSummary
	var input api.ListNotebookInstancesInput
	for {
		output, err := a.api.ListNotebookInstances(a.Context(), &input)
		if err != nil {
			return nil, err
		}

		apiinstances = append(apiinstances, output.NotebookInstances...)
		a.Tracker().SetTotalResources(len(apiinstances))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken

	}

	a.Tracker().SetServiceLabel("Adapting instance...")
	return concurrency.Adapt(apiinstances, a.RootAdapter, a.adaptInstance), nil
}

func (a *adapter) adaptInstance(instance types.NotebookInstanceSummary) (*sagemaker.NotebookInstance, error) {
	metadata := a.CreateMetadataFromARN(*instance.NotebookInstanceArn)

	output, err := a.api.DescribeNotebookInstance(a.Context(), &api.DescribeNotebookInstanceInput{
		NotebookInstanceName: instance.NotebookInstanceName,
	})
	if err != nil {
		return nil, err
	}

	return &sagemaker.NotebookInstance{
		Metadata:             metadata,
		KmsKeyId:             defsecTypes.String(*output.KmsKeyId, metadata),
		DirectInternetAccess: defsecTypes.String(string(output.DirectInternetAccess), metadata),
		NetworkInterfaceId:   defsecTypes.String(*output.NetworkInterfaceId, metadata),
	}, nil
}
