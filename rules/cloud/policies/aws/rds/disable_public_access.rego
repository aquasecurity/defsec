# METADATA
# title: "RDS Publicly Accessible"
# description: "Ensures RDS instances are not launched into the public cloud."
# scope: package
# schemas:
<<<<<<< HEAD:rules/cloud/policies/aws/rds/disable_public_access.rego
# - input: schema["cloud"]
=======
# - input: schema.input
>>>>>>> 7bd3f317 (Added policy to check public access key for rds (#1057)):internal/rules/policies/cloud/policies/aws/rds/disable_public_access.rego
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service: rds
#   severity: HIGH
#   short_code: enable-public-access
#   recommended_action: "Remove the public endpoint from the RDS instance'"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: rds
#           provider: aws
#   terraform:
#       good_examples: "rules/cloud/policies/aws/rds/no_public_db_access.tf.go"
#   cloud_formation:
#       good_examples: "rules/cloud/policies/aws/rds/no_public_db_access.cf.go"

package builtin.aws.rds.aws0180

deny[res] {
	instance := input.aws.rds.instances[_]
	instance.publicaccess.value
	res := result.new("Instance has Public Access enabled", instance.publicaccess)
}
