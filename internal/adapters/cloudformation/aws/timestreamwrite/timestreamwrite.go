package timestreamwrite

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/timestreamwrite"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) timestreamwrite.Timestream_write {
	return timestreamwrite.Timestream_write{
		ListDatabases: getListDatabases(cfFile),
	}
}
