package backup

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/backup"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) backup.Backup {
	return backup.Backup{
		Vaults: getbackupVaults(cfFile),
		Plans:  getbackupPlans(cfFile),
	}
}
