package backup

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/backup"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) backup.Backup {
	return backup.Backup{
		Vaults:         adaptVaults(modules),
		Plans:          adaptPlans(modules),
		RegionSettings: adaptSettings(modules),
	}
}

func adaptVaults(modules terraform.Modules) []backup.Vault {
	var vaults []backup.Vault

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_backup_vault") {
			vaults = append(vaults, adaptVault(resource, module))
		}
	}
	return vaults
}

func adaptPlans(modules terraform.Modules) []backup.Plan {
	var plans []backup.Plan

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_backup_plan") {
			plans = append(plans, adaptPlan(resource, module))
		}
	}
	return plans
}

func adaptSettings(modules terraform.Modules) backup.RegionSettings {
	var RS backup.RegionSettings
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_backup_region_settings") {

			RS = backup.RegionSettings{
				Metadata: resource.GetMetadata(),
			}
		}
	}
	return RS
}

func adaptPlan(resource *terraform.Block, module *terraform.Module) backup.Plan {
	var rules []backup.Rule
	for _, r := range resource.GetBlocks("rule") {

		rule := backup.Rule{
			Metadata: r.GetMetadata(),
			LifeCycle: backup.LifeCycle{
				Metadata:                   r.GetMetadata(),
				DeleteAfterDays:            defsecTypes.IntDefault(0, r.GetMetadata()),
				MoveToColdStorageAfterDays: defsecTypes.IntDefault(0, r.GetMetadata()),
			},
		}

		if lifecyleBlock := r.GetBlock("lifecycle"); lifecyleBlock.IsNotNil() {
			rule.LifeCycle.Metadata = lifecyleBlock.GetMetadata()
			DADAttr := lifecyleBlock.GetAttribute("delete_after")
			rule.LifeCycle.DeleteAfterDays = DADAttr.AsIntValueOrDefault(0, lifecyleBlock)

			CSAAttr := lifecyleBlock.GetAttribute("cold_storage_after")
			rule.LifeCycle.MoveToColdStorageAfterDays = CSAAttr.AsIntValueOrDefault(0, lifecyleBlock)

		}
		rules = append(rules, rule)
	}
	return backup.Plan{
		Metadata: resource.GetMetadata(),
		Rules:    rules,
	}
}

func adaptVault(resource *terraform.Block, module *terraform.Module) backup.Vault {

	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	var policy defsecTypes.StringValue
	policyRes := module.GetReferencingResources(resource, "aws_backup_vault_policy", "backup_vault_name")
	for _, res := range policyRes {
		policy = res.GetAttribute("policy").AsStringValueOrDefault("", res)
	}

	var notifications []backup.VaultNotifications
	notires := module.GetReferencingResources(resource, "aws_backup_vault_notifications", "backup_vault_name")
	for _, res := range notires {
		var events []defsecTypes.StringValue
		eventAttr := res.GetAttribute("backup_vault_events")
		for _, event := range eventAttr.AsStringValues() {
			events = append(events, event)
		}

		notifications = append(notifications, backup.VaultNotifications{
			Metadata:          res.GetMetadata(),
			BackupVaultEvents: events,
		})
	}

	return backup.Vault{
		Metadata:      resource.GetMetadata(),
		Name:          nameVal,
		Arn:           resource.GetAttribute("arn").AsStringValueOrDefault("", resource),
		KeyArn:        resource.GetAttribute("kms_key_arn").AsStringValueOrDefault("", resource),
		Policy:        policy,
		Notifications: notifications,
	}
}
