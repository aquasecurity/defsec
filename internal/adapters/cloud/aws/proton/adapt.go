package proton

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/proton"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/proton"
	aatypes "github.com/aws/aws-sdk-go-v2/service/proton/types"
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
	return "proton"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Proton.ListEnvironmentTemplates, err = a.getEnvironmentTemplate()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getEnvironmentTemplate() ([]proton.EnvironmentTemplate, error) {

	a.Tracker().SetServiceLabel("Discovering Environment Template ...")

	var apiEnvironmentTemplate []aatypes.EnvironmentTemplateSummary
	var input api.ListEnvironmentTemplatesInput
	for {
		output, err := a.api.ListEnvironmentTemplates(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiEnvironmentTemplate = append(apiEnvironmentTemplate, output.Templates...)
		a.Tracker().SetTotalResources(len(apiEnvironmentTemplate))
		if output.Templates == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting Stream Info...")
	return concurrency.Adapt(apiEnvironmentTemplate, a.RootAdapter, a.adaptEnvironmentTemplate), nil
}

func (a *adapter) adaptEnvironmentTemplate(apiEnvironmentTemplate aatypes.EnvironmentTemplateSummary) (*proton.EnvironmentTemplate, error) {

	metadata := a.CreateMetadataFromARN(*apiEnvironmentTemplate.Arn)

	getEncrytpitonKey, err := a.api.GetEnvironmentTemplate(a.Context(), &api.GetEnvironmentTemplateInput{
		Name: apiEnvironmentTemplate.Name,
	})
	if err != nil {
		return nil, err
	}

	var encryptionkey string
	if getEncrytpitonKey.EnvironmentTemplate.EncryptionKey != nil {
		encryptionkey = *getEncrytpitonKey.EnvironmentTemplate.EncryptionKey
	}

	return &proton.EnvironmentTemplate{
		Metadata:      metadata,
		EncryptionKey: defsecTypes.String(encryptionkey, metadata),
	}, nil
}
