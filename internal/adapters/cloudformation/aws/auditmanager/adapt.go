package auditmanager

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/auditmanager"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getAuditSetting(ctx parser.FileContext) (kmskey auditmanager.Setting) {

	getKmsKey := ctx.GetResourcesByType("AWS::AuditManager::Assessment")

	for _, r := range getKmsKey {

		var AWSKMSKeyARN types.StringValue
		keyarn := r.GetProperty("Arn").AsString()
		AWSKMSKeyARN = types.String(keyarn, types.Metadata{})

		ds := auditmanager.Setting{
			Metadata: r.Metadata(),
			KmsKey:   AWSKMSKeyARN,
		}
		kmskey = ds
	}

	return kmskey
}
