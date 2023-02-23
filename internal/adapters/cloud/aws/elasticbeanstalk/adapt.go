package elascticbeanstalk

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticbeanstalk"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
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
	return "elascticbeanstalk"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.ElasticBeanStalk.Environments, err = a.getEnvironments()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getEnvironments() ([]elasticbeanstalk.Environment, error) {

	a.Tracker().SetServiceLabel("Discovering environments..")

	var input api.DescribeEnvironmentsInput

	var apiEnvironments []types.EnvironmentDescription
	for {
		output, err := a.api.DescribeEnvironments(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiEnvironments = append(apiEnvironments, output.Environments...)
		a.Tracker().SetTotalResources(len(apiEnvironments))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting environments...")
	return concurrency.Adapt(apiEnvironments, a.RootAdapter, a.adaptEnvironment), nil
}

func (a *adapter) adaptEnvironment(environment types.EnvironmentDescription) (*elasticbeanstalk.Environment, error) {
	metadata := a.CreateMetadataFromARN(*environment.EnvironmentArn)

	output, err := a.api.DescribeConfigurationSettings(a.Context(), &api.DescribeConfigurationSettingsInput{
		ApplicationName: environment.ApplicationName,
	})
	if err != nil {
		return nil, err
	}

	var settings []elasticbeanstalk.OptionSetting
	for _, s := range output.ConfigurationSettings {
		for _, optionsetting := range s.OptionSettings {
			settings = append(settings, elasticbeanstalk.OptionSetting{
				Metadata:   metadata,
				NameSpace:  defsecTypes.String(*optionsetting.Namespace, metadata),
				OptionName: defsecTypes.String(*optionsetting.OptionName, metadata),
				Value:      defsecTypes.String(*optionsetting.Value, metadata),
			})
		}
	}

	return &elasticbeanstalk.Environment{
		Metadata:       metadata,
		HealthStatus:   defsecTypes.String(string(environment.HealthStatus), metadata),
		OptionSettings: settings,
	}, nil
}
