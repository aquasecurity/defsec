# METADATA
# title: "ECR Repository Tag Immutability"
# description: "Ensures ECR repository image tags cannot be overwritten"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://sysdig.com/blog/toctou-tag-mutability/
# custom:
#   avd_id: AVD-AWS-0192
#   provider: aws
#   service: ecr
#   severity: HIGH
#   short_code: enforce-immutable-repository
#   recommended_action: "Update ECR registry configurations to ensure image tag mutability is set to immutable."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.ecr.aws0192

deny[res] {
	repo := input.aws.ecr.repositories[_]
	not repo.imagetagsimmutable.value
	res := result.new("Repository tags are mutable.", repo.imagetagsimmutable)
}