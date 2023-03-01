package glue

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/glue"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/glue/types"
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
	return "glue"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Glue.SecurityConfigurations, err = a.getSecurityConfigurations()
	if err != nil {
		return err
	}

	state.AWS.Glue.DataCatalogEncryptionSettings, err = a.getEncryptionSettings()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getSecurityConfigurations() ([]glue.SecurityConfiguration, error) {

	a.Tracker().SetServiceLabel("Discovering security configurations...")

	var apisecurityconfigurations []types.SecurityConfiguration
	var input api.GetSecurityConfigurationsInput
	for {
		output, err := a.api.GetSecurityConfigurations(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apisecurityconfigurations = append(apisecurityconfigurations, output.SecurityConfigurations...)
		a.Tracker().SetTotalResources(len(apisecurityconfigurations))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting security configurations...")
	return concurrency.Adapt(apisecurityconfigurations, a.RootAdapter, a.adaptSecurityConfiguration), nil
}

func (a *adapter) adaptSecurityConfiguration(securityconfiguration types.SecurityConfiguration) (*glue.SecurityConfiguration, error) {
	metadata := a.CreateMetadata(*securityconfiguration.Name)

	var cloudWatchEncryption, jobBookmarksEncryption string
	var s3Encryptions []glue.S3Encryption
	if securityconfiguration.EncryptionConfiguration != nil {
		if securityconfiguration.EncryptionConfiguration.CloudWatchEncryption != nil {
			cloudWatchEncryption = string(securityconfiguration.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode)
		}
		if securityconfiguration.EncryptionConfiguration.JobBookmarksEncryption != nil {
			jobBookmarksEncryption = string(securityconfiguration.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode)
		}
		if securityconfiguration.EncryptionConfiguration.S3Encryption != nil {
			for _, e := range securityconfiguration.EncryptionConfiguration.S3Encryption {
				s3Encryptions = append(s3Encryptions, glue.S3Encryption{
					Metadata:         metadata,
					S3EncryptionMode: defsecTypes.String(string(e.S3EncryptionMode), metadata),
				})
			}
		}

	}

	return &glue.SecurityConfiguration{
		Metadata: metadata,
		EncryptionConfiguration: glue.EncryptionConfiguration{
			CloudWatchEncryptionMode:   defsecTypes.String(cloudWatchEncryption, metadata),
			JobBookmarksEncryptionMode: defsecTypes.String(jobBookmarksEncryption, metadata),
			S3Encryptions:              s3Encryptions,
		},
	}, nil
}

func (a *adapter) getEncryptionSettings() (glue.DataCatalogEncryptionSetting, error) {

	a.Tracker().SetServiceLabel("Discovering data catalog encryption settings...")

	var apisettings types.DataCatalogEncryptionSettings
	var settings glue.DataCatalogEncryptionSetting
	var input api.GetDataCatalogEncryptionSettingsInput
	for {
		output, err := a.api.GetDataCatalogEncryptionSettings(a.Context(), &input)
		if err != nil {
			return settings, err
		}
		apisettings = *output.DataCatalogEncryptionSettings
		if output.DataCatalogEncryptionSettings == nil {
			break
		}
	}

	metadata := a.CreateMetadata(*apisettings.EncryptionAtRest.SseAwsKmsKeyId)
	var encryption, kmskeyId string
	if apisettings.EncryptionAtRest != nil {
		encryption = string(apisettings.EncryptionAtRest.CatalogEncryptionMode)
		kmskeyId = *apisettings.EncryptionAtRest.SseAwsKmsKeyId
	}

	settings = glue.DataCatalogEncryptionSetting{
		Metadata: metadata,
		EncryptionAtRest: glue.EncryptionAtRest{
			Metadata:              metadata,
			CatalogEncryptionMode: defsecTypes.String(encryption, metadata),
			SseAwsKmsKeyId:        defsecTypes.String(kmskeyId, metadata),
		},
	}
	return settings, nil
}
