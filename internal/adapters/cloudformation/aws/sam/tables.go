package sam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

func getSimpleTables(cfFile parser.FileContext) (tables []sam.SimpleTable) {

	tableResources := cfFile.GetResourcesByType("AWS::Serverless::SimpleTable")
	for _, r := range tableResources {
		table := sam.SimpleTable{
			Metadata:         r.Metadata(),
			TableName:        r.GetStringProperty("TableName"),
			SSESpecification: getSSESpecification(r),
		}

		tables = append(tables, table)
	}

	return tables
}

func getSSESpecification(r *parser.Resource) sam.SSESpecification {

	spec := sam.SSESpecification{
		Metadata:       r.Metadata(),
		Enabled:        types2.BoolDefault(false, r.Metadata()),
		KMSMasterKeyID: types2.StringDefault("", r.Metadata()),
	}

	if sse := r.GetProperty("SSESpecification"); sse.IsNotNil() {
		spec = sam.SSESpecification{
			Metadata:       sse.Metadata(),
			Enabled:        sse.GetBoolProperty("SSEEnabled"),
			KMSMasterKeyID: sse.GetStringProperty("KMSMasterKeyID"),
		}
	}

	return spec
}
