# METADATA
# title: "Custom Domain TLS Version"
# description: "Ensure API Gateway custom domains are using current minimum TLS version."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# -  https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html
# custom:
#   avd_id: AVD-AWS-0312
#   provider: aws
#   service: apigateway
#   severity: LOW
#   short_code: use_secure_tls_policy
#   recommended_action: "Modify API Gateway custom domain security policy and specify new TLS version."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.apigateway.aws0312

deny[res] {
	domain := input.aws.apigateway.v2.domainnames[_]
	domain.securitypolicy.value != "TLS_1_2"
	res := result.new("API Gateway Custom Domain is using deprecated TLS version", domain.securitypolicy)
}
