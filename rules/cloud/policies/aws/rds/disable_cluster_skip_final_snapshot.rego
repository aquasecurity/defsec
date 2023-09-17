# METADATA
# title: "RDS Cluster Skip Final Snapshot Enabled"
# description: "Ensure skip final snapshot is disabled for RDS clusters."
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_DeleteCluster.html
# custom:
#   avd_id: AVD-AWS-0344
#   provider: aws
#   service: rds
#   severity: MEDIUM
#   short_code: disable-cluster-skip-final-snapshot
#   recommended_action: "Modify the RDS clusters to disable skip final snapshot."
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: rds
#           provider: aws
package PACKAGE_NAME

deny[res] {
	cluster := input.aws.rds.clusters[_]
	cluster.skipfinalsnapshot.value
	res := result.new("Cluster does not have Deletion Protection disabled", cluster.skipfinalsnapshot)
}
