package api_gateway

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/types"

	v1 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v1"

	api "github.com/aws/aws-sdk-go-v2/service/apigateway"
	agTypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
)

func (a *adapter) getDomainNamesv1() ([]v1.DomainName, error) {
	a.Tracker().SetServiceLabel("Discovering v1 domain names...")

	var input api.GetDomainNamesInput
	var apiDomainNames []agTypes.DomainName
	for {
		output, err := a.clientV1.GetDomainNames(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiDomainNames = append(apiDomainNames, output.Items...)
		a.Tracker().SetTotalResources(len(apiDomainNames))
		if output.Position == nil {
			break
		}
		input.Position = output.Position
	}

	a.Tracker().SetServiceLabel("Adapting v1 domain names...")
	return concurrency.Adapt(apiDomainNames, a.RootAdapter, a.adaptDomainNameV1), nil

}

func (a *adapter) adaptDomainNameV1(domain agTypes.DomainName) v1.DomainName {
	metadata := a.CreateMetadata(fmt.Sprintf("/domainnames/%s", *domain.DomainName))
	return v1.DomainName{
		Metadata:       metadata,
		Name:           types.String(*domain.DomainName, metadata),
		SecurityPolicy: types.String(string(domain.SecurityPolicy), metadata),
	}
}
