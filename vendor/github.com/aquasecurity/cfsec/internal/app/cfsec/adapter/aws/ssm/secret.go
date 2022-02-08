package ssm

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/ssm"
)

func getSecrets(ctx parser.FileContext) (secrets []ssm.Secret) {
	for _, r := range ctx.GetResourceByType("AWS::SecretsManager::Secret") {
		secret := ssm.Secret{
			Metadata: r.Metadata(),
			KMSKeyID: r.GetStringProperty("KmsKeyId"),
		}

		secrets = append(secrets, secret)
	}
	return secrets
}
