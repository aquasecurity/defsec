# METADATA
# title: "AWS Backup Compliant Lifecycle Configured"
# description: "Ensure that a compliant lifecycle configuration is enabled for your Amazon Backup plans in order to meet compliance requirements when it comes to security and cost optimization."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/aws-backup/latest/devguide/API_Lifecycle.html
# custom:
#   avd_id: AVD-AWS-0342
#   provider: aws
#   service: backup
#   severity: LOW
#   short_code: complaint_lifecycle_configured
#   recommended_action: "Enable compliant lifecycle configuration for your Amazon Backup plans"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.backup.aws0342

is_lifecycle(rule){
    any([rule.lifecycle.deleteafterdays.value == 0, rule.lifecycle.movetocoldstorageafterdays.value == 0])
}

deny[res] {
	plan := input.aws.backup.plans[_]
	found := [rule | rule = plan.rules[_]; is_lifecycle(rule)]
    count(found) != 0
	res := result.new("Backup plan does not have lifecycle configuration enabled", plan)
}
