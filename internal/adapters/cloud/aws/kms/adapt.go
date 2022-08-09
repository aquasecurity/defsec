package kms

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/kms"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
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
	return "kms"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.KMS.Keys, err = a.getKeys()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getKeys() ([]kms.Key, error) {

	a.Tracker().SetServiceLabel("Discovering keys...")

	var apiKeys []types.KeyListEntry
	var input api.ListKeysInput
	for {
		output, err := a.api.ListKeys(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiKeys = append(apiKeys, output.Keys...)
		a.Tracker().SetTotalResources(len(apiKeys))
		if output.NextMarker == nil {
			break
		}
		input.Marker = output.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting keys...")

	var keys []kms.Key
	for _, apiKey := range apiKeys {
		key, err := a.adaptKey(apiKey)
		if err != nil {
			a.Debug("Failed to adapt key '%s': %s", *apiKey.KeyArn, err)
			continue
		}
		keys = append(keys, *key)
		a.Tracker().IncrementResource()
	}

	return keys, nil
}

func (a *adapter) adaptKey(apiKey types.KeyListEntry) (*kms.Key, error) {

	metadata := a.CreateMetadataFromARN(*apiKey.KeyArn)

	output, err := a.api.DescribeKey(a.Context(), &api.DescribeKeyInput{
		KeyId: apiKey.KeyId,
	})
	if err != nil {
		return nil, err
	}

	return &kms.Key{
		Metadata:        metadata,
		Usage:           defsecTypes.String(string(output.KeyMetadata.KeyUsage), metadata),
		RotationEnabled: defsecTypes.Bool(output.KeyMetadata.ValidTo != nil, metadata),
	}, nil
}
