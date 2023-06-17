package memorydb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/memorydb"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) memorydb.MemoryDB {
	return memorydb.MemoryDB{
		Clusters: getClusters(cfFile),
	}
}
