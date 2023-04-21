package wafv2

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/wafv2"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/wafv2"
	aatypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
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
	return "wafv2"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Wafv2.ListWebACLs, err = a.getListWebACLs2()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getListWebACLs2() ([]wafv2.WebACLs2, error) {

	a.Tracker().SetServiceLabel("Discovering WebACLs v2 list...")

	var apiListWebACLs2 []aatypes.WebACLSummary
	var input api.ListWebACLsInput
	for {
		output, err := a.api.ListWebACLs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiListWebACLs2 = append(apiListWebACLs2, output.WebACLs...)
		a.Tracker().SetTotalResources(len(apiListWebACLs2))
		if output.WebACLs == nil {
			break
		}
		input.NextMarker = output.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting list WebACLs2...")
	return concurrency.Adapt(apiListWebACLs2, a.RootAdapter, a.adaptListWebACLs2), nil
}

func (a *adapter) adaptListWebACLs2(apiListWebACLs2 aatypes.WebACLSummary) (*wafv2.WebACLs2, error) {

	metadata := a.CreateMetadataFromARN(*apiListWebACLs2.ARN)

	var id string
	if apiListWebACLs2.Id != nil {
		id = *apiListWebACLs2.Id
	}

	return &wafv2.WebACLs2{
		Metadata: metadata,
		WebACLId: defsecTypes.String(id, metadata),
	}, nil
}
