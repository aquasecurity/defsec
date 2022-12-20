# METADATA
# title: "Lambda VPC Config"
# description: "Ensures Lambda functions are created in a VPC."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/lambda/latest/dg/vpc.html
# custom:
#   avd_id: AVD-AWS-0305
#   provider: aws
#   service: lambda
#   severity: HIGH
#   short_code: vpc_config
#   recommended_action: "Update the Lambda function with a VPC configuration."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.lambda.aws0305

deny[res] {
	function := input.aws.lambda.functions[_]
    function.vpcconfig.vpcid.value == ""
	res := result.new("Function is not being launched into a VPC'", function.vpcconfig.vpcid)
}
