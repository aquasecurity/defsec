package shield

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ses"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/ses"
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
	return "ses"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.SES.ListIdentities, err = a.getListIdentities()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getListIdentities() ([]ses.Identities, error) {

	a.Tracker().SetServiceLabel("Discovering Identities...")

	var apiListIdentities []string
	var input api.ListIdentitiesInput
	for {
		output, err := a.api.ListIdentities(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiListIdentities = append(apiListIdentities, output.Identities...)
		a.Tracker().SetTotalResources(len(apiListIdentities))
		if output.Identities == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting list Identities...")
	return concurrency.Adapt(apiListIdentities, a.RootAdapter, a.adaptListIdentities), nil
}

func (a *adapter) adaptListIdentities(apiListIdentities string) (*ses.Identities, error) {

	metadata := a.CreateMetadata(apiListIdentities)
	output, err := a.api.GetIdentityDkimAttributes(a.Context(), &api.GetIdentityDkimAttributesInput{})
	if output.DkimAttributes != nil {
		return nil, err
	}

	var verificationStatus string
	var dkimEnabled bool
	return &ses.Identities{
		Metadata: metadata,
		DkimAttributes: ses.DkimAttributes{
			Metadata:               metadata,
			DkimVerificationStatus: defsecTypes.String(verificationStatus, metadata),
			DkimEnabled:            defsecTypes.Bool(dkimEnabled, metadata),
		},
	}, nil
}
