package glue

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iotsitewise"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/iotsitewise"
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
	return "iotsitewise"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.IoTSiteWise.DefaultEncryptionConfiguration, err = a.getEncryptionConfiguration()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getEncryptionConfiguration() (iotsitewise.DefaultEncryptionConfiguration, error) {

	a.Tracker().SetServiceLabel("Discovering encryption configuration...")

	var encypconfiguration iotsitewise.DefaultEncryptionConfiguration
	var input api.DescribeDefaultEncryptionConfigurationInput

	output, err := a.api.DescribeDefaultEncryptionConfiguration(a.Context(), &input)
	if err != nil {
		return encypconfiguration, err
	}
	metadata := a.CreateMetadataFromARN(*output.KmsKeyArn)

	encypconfiguration = iotsitewise.DefaultEncryptionConfiguration{
		Metadata:       metadata,
		KmsKeyArn:      defsecTypes.String(*output.KmsKeyArn, metadata),
		EncryptionType: defsecTypes.String(string(output.EncryptionType), metadata),
	}

	return encypconfiguration, nil
}
