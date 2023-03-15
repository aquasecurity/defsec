# METADATA
# title: "RDS Publicly Accessible"
# description: "Ensures RDS instances are not launched into the public cloud."
# scope: package
# schemas:
# - input: schema["cloud"]
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
