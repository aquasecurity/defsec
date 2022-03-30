package sam

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
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
		Enabled:        types.BoolDefault(false, r.Metadata()),
		KMSMasterKeyID: types.StringDefault("", r.Metadata()),
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
