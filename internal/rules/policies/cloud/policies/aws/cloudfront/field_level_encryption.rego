# METADATA
# title: "CloudFront Distribution Field-Level Encryption"
# description: "Ensure that field-level encryption is enabled for your Amazon CloudFront web distributions."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/field-level-encryption.html
# custom:
#   avd_id: AVD-AWS-0315
#   provider: aws
#   service: cloudfront
#   severity: LOW
#   short_code: field_level_encryption
#   recommended_action: "Enable field-level encryption for CloudFront distributions."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudfront.aws0315

deny[res] {
    distribution := input.aws.cloudfront.distributions[_]
    distribution.defaultcachebehaviour.fieldlevelencryptionid.value == ""
    res := result.new("Distribution does not have field level encryption enabled", distribution.defaultcachebehaviour.fieldlevelencryptionid)
}