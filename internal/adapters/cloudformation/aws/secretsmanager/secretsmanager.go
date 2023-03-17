package secretsmanager

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/secretsmanager"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) secretsmanager.SecretsManager {
	return secretsmanager.SecretsManager{
		Secrets: getSecrets(cfFile),
	}
}
