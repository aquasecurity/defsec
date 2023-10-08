# METADATA
# title: "API Stage-Level Cache Encryption"
# description: "Ensure that your Amazon API Gateway REST APIs are configured to encrypt API cached responses."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# -  https://docs.aws.amazon.com/apigateway/latest/developerguide/data-protection-encryption.html
# custom:
#   avd_id: AVD-AWS-0309
#   provider: aws
#   service: apigateway
#   severity: LOW
#   short_code: enable_cache_cluster
#   recommended_action: "Modify API Gateway API stages to enable encryption on cache data"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.apigateway.aws0309

deny[res] {
	api := input.aws.apigateway.v1.apis[_]
    stage := api.stages[_]
    setting := stage.restmethodsettings[_]
	all([setting.cacheenabled.value, setting.cachedataencrypted.value == false])
	res := result.new("API Gateway stage does not encrypt cache data", setting)
}
