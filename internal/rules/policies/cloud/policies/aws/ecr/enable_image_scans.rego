# METADATA
# title: "ECR Image Scans"
# description: "Ensure ECR repository has image scans disabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html
# custom:
#   avd_id: AVD-AWS-0191
#   provider: aws
#   service: ecr
#   severity: HIGH
#   short_code: enable-image-scans
#   recommended_action: "Repository image scans should be enabled to ensure vulnerable software can be discovered and remediated as soon as possible."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.ecr.aws0191

deny[res] {
	repo := input.aws.ecr.repositories[_]
	not repo.imagescanning.scanonpush.value
	res := result.new("Image scanning is not enabled.", repo.imagescanning.scanonpush)
}
