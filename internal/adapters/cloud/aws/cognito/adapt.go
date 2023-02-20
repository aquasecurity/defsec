package cognito

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cognito"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
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
	return "cognito"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Cognito.UserPool, err = a.getPools()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getPools() ([]cognito.UserPool, error) {

	a.Tracker().SetServiceLabel("Discovering pools.")

	var apipools []types.UserPoolDescriptionType
	var input api.ListUserPoolsInput
	for {
		output, err := a.client.ListUserPools(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apipools = append(apipools, output.UserPools...)
		a.Tracker().SetTotalResources(len(apipools))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting pipelines...")
	return concurrency.Adapt(apipools, a.RootAdapter, a.adaptPool), nil
}

func (a *adapter) adaptPool(pool types.UserPoolDescriptionType) (*cognito.UserPool, error) {

	output, err := a.client.DescribeUserPool(a.Context(), &api.DescribeUserPoolInput{
		UserPoolId: pool.Id,
	})
	if err != nil {
		return nil, err
	}

	metadata := a.CreateMetadataFromARN(*output.UserPool.Arn)

	return &cognito.UserPool{
		Metadata:         metadata,
		Id:               defsecTypes.String(*pool.Id, metadata),
		MfaConfiguration: defsecTypes.String(string(output.UserPool.MfaConfiguration), metadata),
	}, nil
}
