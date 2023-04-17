package auditmanager

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/auditmanager"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getAuditSetting(ctx parser.FileContext) auditmanager.Setting {

	auditSettings := auditmanager.Setting{
		Metadata: types.NewUnmanagedMetadata(),
		KmsKey:   types.StringDefault("", ctx.Metadata()),
	}

	kmsKeyResources := ctx.GetResourcesByType("AWS::AuditManager::Assessment")

	if len(kmsKeyResources) == 0 {
		return auditSettings
	}

	return auditmanager.Setting{
		Metadata: kmsKeyResources[0].Metadata(),
		KmsKey:   iskmsKeyVal(kmsKeyResources[0]),
	}
}

func iskmsKeyVal(r *parser.Resource) types.StringValue {
	kmsKeyVal := types.StringUnresolvable(r.Metadata())

	return kmsKeyVal
}
