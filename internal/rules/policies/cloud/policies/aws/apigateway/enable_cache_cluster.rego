# METADATA
# title: "API Gateway Response Caching"
# description: "Ensure that response caching is enabled for your Amazon API Gateway REST APIs."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# -  https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html
# custom:
#   avd_id: AVD-AWS-0307
#   provider: aws
#   service: apigateway
#   severity: LOW
#   short_code: enable_cache_cluster
#   recommended_action: "Modify API Gateway API stages to enable API cache"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.apigateway.aws0307

deny[res] {
	api := input.aws.apigateway.v1.apis[_]
    stage := api.stages[_]
	not stage.cacheclusterenabled.value
	res := result.new("Response caching is not enabled for API Gateway API stages", stage.cacheclusterenabled)
}
