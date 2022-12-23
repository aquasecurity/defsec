# METADATA
# title: "Lambda Tracing Enabled"
# description: "Ensures AWS Lambda functions have active tracing for X-Ray."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html
# custom:
#   avd_id: AVD-AWS-0311
#   provider: aws
#   service: lambda
#   severity: LOW
#   short_code: enable_tracing
#   recommended_action: "Modify Lambda functions to activate tracing"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.lambda.aws0311

deny[res] {
	function := input.aws.lambda.functions[_]
    function.tracing.mode.value != "Active"
	res := result.new("Function does not have active tracing", function.tracing.mode)
}