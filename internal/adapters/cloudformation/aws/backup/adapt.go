package backup

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/backup"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getbackupVaults(ctx parser.FileContext) (vaults []backup.Vault) {

	vaultResources := ctx.GetResourcesByType("AWS::Backup::BackupVault")

	for _, r := range vaultResources {
		vault := backup.Vault{
			Metadata:      r.Metadata(),
			Name:          r.GetStringProperty("BackupVaultName"),
			Arn:           r.GetStringProperty("BackupVaultArn"),
			KeyArn:        r.GetStringProperty("EncryptionKeyArn"),
			Policy:        r.GetStringProperty("AccessPolicy"),
			Notifications: getnotifications(r),
		}
		vaults = append(vaults, vault)
	}
	return vaults
}

func getnotifications(r *parser.Resource) (notifications []backup.VaultNotifications) {
	notificationList := r.GetProperty("Notifications")
	if notificationList.IsNil() || !notificationList.IsList() {
		return
	}

	for _, a := range notificationList.AsList() {

		notification := backup.VaultNotifications{
			Metadata:          notificationList.Metadata(),
			BackupVaultEvents: getevents(a),
		}
		notifications = append(notifications, notification)
	}
	return notifications
}

func getevents(r *parser.Property) (events []types.StringValue) {

	eventList := r.GetProperty("BackupVaultEvents")

	if eventList.IsNil() || eventList.IsNotList() {
		return events
	}

	for _, event := range eventList.AsList() {
		events = append(events, event.AsStringValue())
	}
	return events
}

func getbackupPlans(ctx parser.FileContext) (plans []backup.Plan) {

	backupplanResources := ctx.GetResourcesByType("AWS::Backup::BackupPlan")

	for _, res := range backupplanResources {
		planres := res.GetProperty("BackupPlan")
		if planres.IsNil() || !planres.IsList() {
			return
		}
		for _, r := range planres.AsList() {
			plan := backup.Plan{
				Metadata: r.Metadata(),
				Rules:    getplanrules(r),
			}
			plans = append(plans, plan)
		}
	}
	return plans
}

func getplanrules(r *parser.Property) (rules []backup.Rule) {
	ruleList := r.GetProperty("BackupPlanRule")
	if ruleList.IsNil() || !ruleList.IsList() {
		return
	}

	for _, a := range ruleList.AsList() {
		rule := backup.Rule{
			Metadata: ruleList.Metadata(),
			LifeCycle: backup.LifeCycle{
				Metadata:                   ruleList.Metadata(),
				DeleteAfterDays:            a.GetIntProperty("Lifecycle.DeleteAfterDays"),
				MoveToColdStorageAfterDays: a.GetIntProperty("Lifecycle.MoveToColdStorageAfterDays"),
			},
		}
		rules = append(rules, rule)
	}
	return rules
}
