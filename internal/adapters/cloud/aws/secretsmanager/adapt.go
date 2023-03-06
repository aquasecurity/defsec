package secretsmanager

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/secretsmanager"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
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
	return "sacretsmanager"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.SecretsManager.Secrets, err = a.getSecrets()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getSecrets() ([]secretsmanager.Secret, error) {

	a.Tracker().SetServiceLabel("Discovering secrets...")

	var apisecrets []types.SecretListEntry
	var input api.ListSecretsInput
	for {
		output, err := a.api.ListSecrets(a.Context(), &input)
		if err != nil {
			return nil, err
		}

		apisecrets = append(apisecrets, output.SecretList...)
		a.Tracker().SetTotalResources(len(apisecrets))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken

	}

	a.Tracker().SetServiceLabel("Adapting secrets...")
	return concurrency.Adapt(apisecrets, a.RootAdapter, a.adaptSecret), nil
}

func (a *adapter) adaptSecret(secret types.SecretListEntry) (*secretsmanager.Secret, error) {

	output, err := a.api.DescribeSecret(a.Context(), &api.DescribeSecretInput{
		SecretId: secret.ARN,
	})
	if err != nil {
		return nil, err
	}

	metadata := a.CreateMetadataFromARN(*output.ARN)

	var days int
	if output.RotationRules != nil {
		days = int(*output.RotationRules.AutomaticallyAfterDays)
	}

	var tags []secretsmanager.Tag
	for range output.Tags {
		tags = append(tags, secretsmanager.Tag{
			Metadata: metadata,
		})
	}

	return &secretsmanager.Secret{
		Metadata:               metadata,
		Arn:                    defsecTypes.String(*output.ARN, metadata),
		KmsKeyId:               defsecTypes.String(*output.KmsKeyId, metadata),
		RotationEnabled:        defsecTypes.Bool(*output.RotationEnabled, metadata),
		AutomaticallyAfterDays: defsecTypes.Int(days, metadata),
		Tags:                   tags,
	}, nil
}
