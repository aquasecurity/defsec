# METADATA
# title: "API Gateway Tracing Enabled"
# description: "Ensures that Amazon API Gateway API stages have tracing enabled for AWS X-Ray."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# -  https://docs.aws.amazon.com/xray/latest/devguide/xray-services-apigateway.html
# custom:
#   avd_id: AVD-AWS-0306
#   provider: aws
#   service: apigateway
#   severity: LOW
#   short_code: enable_tracing
#   recommended_action: "Enable tracing on API Gateway API stages"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.apigateway.aws0306

deny[res] {
	api := input.aws.apigateway.v1.apis[_]
    stage := api.stages[_]
	not stage.xraytracingenabled.value
	res := result.new("API Gateway API stage does not have tracing enabled", stage.xraytracingenabled)
}
