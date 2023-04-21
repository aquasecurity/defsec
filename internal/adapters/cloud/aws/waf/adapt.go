package waf

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/waf"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/waf"
	aatypes "github.com/aws/aws-sdk-go-v2/service/waf/types"
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
	return "waf"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Waf.ListWebACLs, err = a.getListWebACLs()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getListWebACLs() ([]waf.ListACLs, error) {

	a.Tracker().SetServiceLabel("Discovering WebACLs v1 list...")

	var apiListWebACLs []aatypes.WebACLSummary
	var input api.ListWebACLsInput
	for {
		output, err := a.api.ListWebACLs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiListWebACLs = append(apiListWebACLs, output.WebACLs...)
		a.Tracker().SetTotalResources(len(apiListWebACLs))
		if output.WebACLs == nil {
			break
		}
		input.NextMarker = output.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting list WebACLs...")
	return concurrency.Adapt(apiListWebACLs, a.RootAdapter, a.adaptListWebACLs), nil
}

func (a *adapter) adaptListWebACLs(apiListWebACLs aatypes.WebACLSummary) (*waf.ListACLs, error) {

	metadata := a.CreateMetadata(*apiListWebACLs.WebACLId)

	var webaclid string
	if apiListWebACLs.WebACLId != nil {
		webaclid = *apiListWebACLs.WebACLId
	}

	return &waf.ListACLs{
		Metadata:  metadata,
		WebACLsID: defsecTypes.String(webaclid, metadata),
	}, nil
}
