# METADATA
# title: "API Gateway Default Endpoint Disabled"
# description: "EEnsure default execute-api endpoint is disabled for your API Gateway."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# -  https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html
# custom:
#   avd_id: AVD-AWS-0308
#   provider: aws
#   service: apigateway
#   severity: LOW
#   short_code: disable_default_endpoint
#   recommended_action: "Modify API Gateway to disable default execute-api endpoint."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.apigateway.aws0308

deny[res] {
	api := input.aws.apigateway.v1.apis[_]
	api.disableexecuteapiendpoint.value
	res := result.new("API Gateway is accessible through default endpoint", api.disableexecuteapiendpoint)
}
