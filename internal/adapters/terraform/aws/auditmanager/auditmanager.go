package auditmanager

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/auditmanager"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) auditmanager.AuditManager {
	return auditmanager.AuditManager{
		Settings: getSettingKmsKey(modules),
	}
}

func getSettingKmsKey(modules terraform.Modules) auditmanager.Setting {
	auditmanagerSettings := auditmanager.Setting{
		Metadata: defsecTypes.NewUnmanagedMetadata(),
		KmsKey:   defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
	}

	for _, resource := range modules.GetResourcesByType("aws_auditmanager_account_registration") {
		auditmanagerSettings.Metadata = resource.GetMetadata()
		auditmanagerSettings.KmsKey = resource.GetAttribute("kms_key").AsStringValueOrDefault("", resource)
	}

	return auditmanagerSettings
}
