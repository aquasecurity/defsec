package auditmanager

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/auditmanager"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) auditmanager.AuditManager {
	return auditmanager.AuditManager{
		Settings: getAuditSetting(cfFile),
	}
}
