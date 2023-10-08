# METADATA
# title: "API Gateway WAF Enabled"
# description: "EnsurAPI Gateway WAF Enabledes that API Gateway APIs are associated with a Web Application Firewall."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# -  https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html
# custom:
#   avd_id: AVD-AWS-0310
#   provider: aws
#   service: apigateway
#   severity: LOW
#   short_code: enable_waf
#   recommended_action: "Associate API Gateway API with Web Application Firewall"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.apigateway.aws0310

deny[res] {
	api := input.aws.apigateway.v1.apis[_]
    stage := api.stages[_]
	stage.webaclarn.value == ""
	res := result.new("API Gateway Stage does not have WAF enabled", stage)
}
