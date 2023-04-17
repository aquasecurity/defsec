package apprunner

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/apprunner"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/apprunner"
	aatypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
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
	return "apprunner"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {
	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())

	var err error
	state.AWS.Apprunner.ListServices, err = a.getListServices()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getListServices() ([]apprunner.ListService, error) {
	a.Tracker().SetServiceLabel(" apprunner list service...")

	var input api.ListServicesInput
	var apiListService []aatypes.ServiceSummary

	for {
		output, err := a.api.ListServices(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiListService = append(apiListService, output.ServiceSummaryList...)

		a.Tracker().SetTotalResources(len(apiListService))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken

	}
	a.Tracker().SetServiceLabel("Adapting ListService...")
	return concurrency.Adapt(apiListService, a.RootAdapter, a.adaptListService), nil

}

func (a *adapter) adaptListService(apiListService aatypes.ServiceSummary) (*apprunner.ListService, error) {

	metadata := a.CreateMetadataFromARN(*apiListService.ServiceArn)
	var arn string
	if apiListService.ServiceArn != nil {
		arn = *apiListService.ServiceArn
	}

	output, err := a.api.DescribeService(a.Context(), &api.DescribeServiceInput{
		ServiceArn: apiListService.ServiceArn,
	})

	if err != nil {
		return nil, err
	}

	var keyid string
	if output.Service.EncryptionConfiguration.KmsKey != nil {
		keyid = *output.Service.EncryptionConfiguration.KmsKey
	}

	return &apprunner.ListService{
		Metadata:   metadata,
		ServiceArn: types.String(arn, metadata),
		KmsKey:     types.String(keyid, metadata),
	}, nil

}
