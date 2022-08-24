package keyvault

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type KeyVault struct {
	Vaults []Vault
}

type Vault struct {
	defsecTypes.Metadata
	Secrets                 []Secret
	Keys                    []Key
	EnablePurgeProtection   defsecTypes.BoolValue
	SoftDeleteRetentionDays defsecTypes.IntValue
	NetworkACLs             NetworkACLs
}

type NetworkACLs struct {
	defsecTypes.Metadata
	DefaultAction defsecTypes.StringValue
}

type Key struct {
	defsecTypes.Metadata
	ExpiryDate defsecTypes.TimeValue
}

type Secret struct {
	defsecTypes.Metadata
	ContentType defsecTypes.StringValue
	ExpiryDate  defsecTypes.TimeValue
}
