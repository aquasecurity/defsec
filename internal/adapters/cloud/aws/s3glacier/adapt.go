package s3glacier

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3glacier"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/glacier"
	"github.com/aws/aws-sdk-go-v2/service/glacier/types"
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
	return "s3glacier"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.S3Glacier.Vaults, err = a.getVaults()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getVaults() ([]s3glacier.Vault, error) {

	a.Tracker().SetServiceLabel("Discovering vaults...")

	var apivaults []types.DescribeVaultOutput
	var input api.ListVaultsInput
	for {
		output, err := a.api.ListVaults(a.Context(), &input)
		if err != nil {
			return nil, err
		}

		apivaults = append(apivaults, output.VaultList...)
		a.Tracker().SetTotalResources(len(apivaults))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker

	}

	a.Tracker().SetServiceLabel("Adapting vault...")
	return concurrency.Adapt(apivaults, a.RootAdapter, a.adaptVault), nil
}

func (a *adapter) adaptVault(vault types.DescribeVaultOutput) (*s3glacier.Vault, error) {
	metadata := a.CreateMetadataFromARN(*vault.VaultARN)

	output, err := a.api.GetVaultAccessPolicy(a.Context(), &api.GetVaultAccessPolicyInput{
		VaultName: vault.VaultName,
	})
	if err != nil {
		return nil, err
	}

	return &s3glacier.Vault{
		Metadata: metadata,
		Policy:   defsecTypes.String(*output.Policy.Policy, metadata),
	}, nil
}
