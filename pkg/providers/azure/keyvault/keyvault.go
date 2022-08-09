package keyvault

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type KeyVault struct {
	Vaults []Vault
}

type Vault struct {
	types2.Metadata
	Secrets                 []Secret
	Keys                    []Key
	EnablePurgeProtection   types2.BoolValue
	SoftDeleteRetentionDays types2.IntValue
	NetworkACLs             NetworkACLs
}

type NetworkACLs struct {
	types2.Metadata
	DefaultAction types2.StringValue
}

type Key struct {
	types2.Metadata
	ExpiryDate types2.TimeValue
}

type Secret struct {
	types2.Metadata
	ContentType types2.StringValue
	ExpiryDate  types2.TimeValue
}
