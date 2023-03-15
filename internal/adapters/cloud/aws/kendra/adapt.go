package kendra

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/kendra"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/kendra"
	aatypes "github.com/aws/aws-sdk-go-v2/service/kendra/types"
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
	return "kendra"
}
//Adapting for api call

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Kendra.ListIndices, err = a.getListIndex()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getListIndex() ([]kendra.ListIndices, error) {

	a.Tracker().SetServiceLabel("Discovering ListIndices...")

	var apiListIndex []aatypes.IndexConfigurationSummary
	var input api.ListIndicesInput
	for {
		output, err := a.api.ListIndices(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiListIndex = append(apiListIndex, output.IndexConfigurationSummaryItems...)
		a.Tracker().SetTotalResources(len(apiListIndex))
		if output.IndexConfigurationSummaryItems == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting List Indices...")
	return concurrency.Adapt(apiListIndex, a.RootAdapter, a.adaptListIndex), nil
}

func (a *adapter) adaptListIndex(index aatypes.IndexConfigurationSummary) (*kendra.ListIndices, error) {

	metadata := a.CreateMetadata(*index.Name)

	getkey, err := a.api.DescribeIndex(a.Context(), &api.DescribeIndexInput{
		Id: index.Id,
	})
	if err != nil {
		return nil, err
	}

	var key string
	if getkey.ServerSideEncryptionConfiguration.KmsKeyId != nil {
		key = *getkey.ServerSideEncryptionConfiguration.KmsKeyId
	}

	return &kendra.ListIndices{
		Metadata: metadata,
		KmsKey: kendra.KmsKey{
			Metadata: metadata,
			KmsKeyId: defsecTypes.String(key, metadata),
		},
	}, nil
}
