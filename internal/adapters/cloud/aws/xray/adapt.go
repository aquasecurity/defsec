package xray

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/xray"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/xray"
	"github.com/aws/aws-sdk-go-v2/service/xray/types"
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
	return "xray"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Xray.EncryptionConfig, err = a.getEncryptionConfig()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getEncryptionConfig() (xray.Configuration, error) {

	a.Tracker().SetServiceLabel("Discovering Encryption Configuration ...")

	var encryptionconfiguration xray.Configuration
	var input api.GetEncryptionConfigInput
	var apiconfig types.EncryptionConfig

	output, err := a.api.GetEncryptionConfig(a.Context(), &input)
	if err != nil {
		return encryptionconfiguration, err
	}
	metadata := a.CreateMetadata(*output.EncryptionConfig.KeyId)
	var key_id string
	if apiconfig.KeyId != nil {
		key_id = *apiconfig.KeyId
	}

	encryptionconfiguration = xray.Configuration{
		Metadata: metadata,
		KeyId:    defsecTypes.String(key_id, metadata),
	}

	return encryptionconfiguration, nil
}
