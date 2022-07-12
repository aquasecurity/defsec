package api_gateway

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/state"
	apiv1 "github.com/aws/aws-sdk-go-v2/service/apigateway"
	apiv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

type adapter struct {
	*aws.RootAdapter
	clientV1 *apiv1.Client
	clientV2 *apiv2.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "api-gateway"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.clientV1 = apiv1.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.APIGateway.V1.DomainNames, err = a.getDomainNamesv1()
	if err != nil {
		return err
	}

	state.AWS.APIGateway.V1.APIs, err = a.getAPIsV1()
	if err != nil {
		return err
	}

	state.AWS.APIGateway.V2.DomainNames, err = a.getDomainNamesV2()
	if err != nil {
		return err
	}

	state.AWS.APIGateway.V2.APIs, err = a.getAPIsV2()
	if err != nil {
		return err
	}

	return nil
}
