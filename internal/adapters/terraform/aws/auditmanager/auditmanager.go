package auditmanager

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/auditmanager"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) auditmanager.AuditManager {
	return auditmanager.AuditManager{
		Settings: getSettingKmsKey(modules),
	}
}

func getSettingKmsKey(modules terraform.Modules) (kmskey auditmanager.Setting) {
	for _, resource := range modules.GetResourcesByType("aws_auditmanager_account_registration") {
		kmskey = adaptSettingKmskey(resource, modules)
	}

	return kmskey
}

func adaptSettingKmskey(resource *terraform.Block, modules terraform.Modules) auditmanager.Setting {

	return auditmanager.Setting{
		Metadata: resource.GetMetadata(),
		KmsKey:   resource.GetAttribute("kms_key").AsStringValueOrDefault("", resource),
	}
}
