package backup

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/backup"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/backup"
	types "github.com/aws/aws-sdk-go-v2/service/backup/types"
)

type adapter struct {
	*aws.RootAdapter
	client *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "backup"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Backup.Vaults, err = a.getbackupVaults()
	if err != nil {
		return err
	}

	state.AWS.Backup.Plans, err = a.getbackupPlans()
	if err != nil {
		return err
	}

	state.AWS.Backup.RegionSettings, err = a.getbackupRegionSettings()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getbackupVaults() ([]backup.Vault, error) {

	a.Tracker().SetServiceLabel("Discovering vaults...")

	var apivaults []types.BackupVaultListMember
	var input api.ListBackupVaultsInput
	for {
		output, err := a.client.ListBackupVaults(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apivaults = append(apivaults, output.BackupVaultList...)
		a.Tracker().SetTotalResources(len(apivaults))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting vaults...")
	return concurrency.Adapt(apivaults, a.RootAdapter, a.adaptVault), nil

}

func (a *adapter) adaptVault(vaultapi types.BackupVaultListMember) (*backup.Vault, error) {

	metadata := a.CreateMetadataFromARN(*vaultapi.BackupVaultArn)

	vault, err := a.client.GetBackupVaultAccessPolicy(a.Context(), &api.GetBackupVaultAccessPolicyInput{
		BackupVaultName: vaultapi.BackupVaultName,
	})
	if err != nil {
		return nil, err
	}

	var notifications []backup.VaultNotifications
	notification, err := a.client.GetBackupVaultNotifications(a.Context(), &api.GetBackupVaultNotificationsInput{
		BackupVaultName: vault.BackupVaultName,
	})
	if err != nil {
		return nil, err
	}
	var events []defsecTypes.StringValue
	for _, event := range notification.BackupVaultEvents {
		events = append(events, defsecTypes.String(string(event), metadata))
	}

	notifications = append(notifications, backup.VaultNotifications{
		Metadata:          metadata,
		BackupVaultEvents: events,
	})

	var name, arn, keyarn, policy string
	if vault.BackupVaultName != nil {
		name = *vault.BackupVaultName
	}

	if vault.BackupVaultArn != nil {
		arn = *vault.BackupVaultArn
	}

	if vault.Policy != nil {
		policy = *vault.Policy
	}

	if vaultapi.EncryptionKeyArn != nil {
		keyarn = *vaultapi.EncryptionKeyArn
	}

	return &backup.Vault{
		Metadata:      metadata,
		Name:          defsecTypes.String(name, metadata),
		Arn:           defsecTypes.String(arn, metadata),
		KeyArn:        defsecTypes.String(keyarn, metadata),
		Policy:        defsecTypes.String(policy, metadata),
		Notifications: notifications,
	}, nil
}

func (a *adapter) getbackupPlans() ([]backup.Plan, error) {

	a.Tracker().SetServiceLabel("Discovering plans...")

	var apiplans []types.BackupPlansListMember
	var input api.ListBackupPlansInput
	for {
		output, err := a.client.ListBackupPlans(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiplans = append(apiplans, output.BackupPlansList...)
		a.Tracker().SetTotalResources(len(apiplans))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting vaults...")
	return concurrency.Adapt(apiplans, a.RootAdapter, a.adaptPlan), nil

}

func (a *adapter) adaptPlan(planapi types.BackupPlansListMember) (*backup.Plan, error) {

	metadata := a.CreateMetadataFromARN(*planapi.BackupPlanArn)

	plan, err := a.client.GetBackupPlan(a.Context(), &api.GetBackupPlanInput{
		BackupPlanId: planapi.BackupPlanId,
	})
	if err != nil {
		return nil, err
	}

	var rule []backup.Rule
	for _, r := range plan.BackupPlan.Rules {

		var DAD, MTCSAD int
		if r.Lifecycle != nil {
			if r.Lifecycle.DeleteAfterDays != nil {
				DAD = int(*r.Lifecycle.DeleteAfterDays)
			}
			if r.Lifecycle.MoveToColdStorageAfterDays != nil {
				MTCSAD = int(*r.Lifecycle.MoveToColdStorageAfterDays)
			}
		}
		rule = append(rule, backup.Rule{
			Metadata: metadata,
			LifeCycle: backup.LifeCycle{
				Metadata:                   metadata,
				DeleteAfterDays:            defsecTypes.Int(DAD, metadata),
				MoveToColdStorageAfterDays: defsecTypes.Int(MTCSAD, metadata),
			},
		})
	}
	return &backup.Plan{
		Metadata: metadata,
		Rules:    rule,
	}, nil
}

func (a *adapter) getbackupRegionSettings() (backup.RegionSettings, error) {

	a.Tracker().SetServiceLabel("Discovering regionsettings...")

	var input api.DescribeRegionSettingsInput
	output, err := a.client.DescribeRegionSettings(a.Context(), &input)

	metadata := a.CreateMetadata(fmt.Sprintf("workgroup/%s", output.ResultMetadata))

	return backup.RegionSettings{
		Metadata: metadata,
	}, err

}
