package dms

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/dms"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) dms.DMS {
	return dms.DMS{
		ReplicationInstances: getReplicationInstances(cfFile),
	}
}
