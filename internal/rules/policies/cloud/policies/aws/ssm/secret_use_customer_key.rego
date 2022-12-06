# METADATA
# title: "SSM customer managed key"
# description: "Secrets Manager should use customer managed keys"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt
# custom:
#   avd_id: AVD-AWS-0203
#   provider: aws
#   service: ssm
#   severity: LOW
#   short_code: secret-use-customer-key
#   recommended_action: "Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explicitly.`"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.ssm.aws0203

import github.com.aquasecurity.defsec.pkg.providers.aws.kms.kms.rego

deny[res] {
	secret := input.aws.ssm.secrets[_]
	secret.kmskeyid.value == ""
	res := result.new("Secret is not encrypted with a customer managed key.", secret.kmskeyid)
}{
    secret := input.aws.ssm.secrets[_]
	secret.kmskeyid.value != ""
	is_aws_managed(secret.kmskeyid.value) == true
	res := result.new("Secret explicitly uses the default key.", secret.kmskeyid)
}
