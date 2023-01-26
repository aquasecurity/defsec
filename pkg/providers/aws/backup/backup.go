package backup

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Backup struct {
	Vaults         []Vault
	Plans          []Plan
	RegionSettings RegionSettings
}

type RegionSettings struct {
	Metadata defsecTypes.Metadata
}

type Vault struct {
	Metadata      defsecTypes.Metadata
	Name          defsecTypes.StringValue
	Arn           defsecTypes.StringValue
	KeyArn        defsecTypes.StringValue
	Policy        defsecTypes.StringValue
	Notifications []VaultNotifications
}

type VaultNotifications struct {
	Metadata          defsecTypes.Metadata
	BackupVaultEvents []defsecTypes.StringValue
}

type Plan struct {
	Metadata defsecTypes.Metadata
	Rules    []Rule
}

type Rule struct {
	Metadata  defsecTypes.Metadata
	LifeCycle LifeCycle
}

type LifeCycle struct {
	Metadata                   defsecTypes.Metadata
	DeleteAfterDays            defsecTypes.IntValue
	MoveToColdStorageAfterDays defsecTypes.IntValue
}
