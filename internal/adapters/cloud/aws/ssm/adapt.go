package ssm

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	defsecTypes "github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ssm"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
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
	return "ssm"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.SSM.Secrets, err = a.getSecrets()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getSecrets() ([]ssm.Secret, error) {

	a.Tracker().SetServiceLabel("Discovering secrets...")

	var apiSecrets []types.SecretListEntry
	var input api.ListSecretsInput
	for {
		output, err := a.api.ListSecrets(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiSecrets = append(apiSecrets, output.SecretList...)
		a.Tracker().SetTotalResources(len(apiSecrets))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting secrets...")

	var secrets []ssm.Secret
	for _, apiCluster := range apiSecrets {
		secret, err := a.adaptSecret(apiCluster)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, *secret)
		a.Tracker().IncrementResource()
	}

	return secrets, nil
}

func (a *adapter) adaptSecret(apiSecret types.SecretListEntry) (*ssm.Secret, error) {

	metadata := a.CreateMetadataFromARN(*apiSecret.ARN)

	var kmsKeyId string
	if apiSecret.KmsKeyId != nil {
		kmsKeyId = *apiSecret.KmsKeyId
	}

	return &ssm.Secret{
		Metadata: metadata,
		KMSKeyID: defsecTypes.String(kmsKeyId, metadata),
	}, nil
}
