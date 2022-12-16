# METADATA
# title: "API Gateway Content Encoding"
# description: "Ensures that Amazon API Gateway APIs have content encoding enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-gzip-compression-decompression.html
# custom:
#   avd_id: AVD-AWS-0219
#   provider: aws
#   service: apigateway
#   severity: HIGH
#   short_code: content_encoding
#   recommended_action: "Enable content encoding and set minimum compression size of API Gateway API response"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.apigateway.aws0219

deny[res] {
	api := input.aws.apigateway.v1.apis[_]
	not api.minimumcompressionsize
	res := result.new("API Gateway does not have content encoding enabled", api)
}
