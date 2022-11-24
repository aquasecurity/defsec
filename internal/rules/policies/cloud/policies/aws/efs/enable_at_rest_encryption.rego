# METADATA
# title: "EFS Encryption Enabled"
# description: "Ensures that EFS volumes are encrypted at rest"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/efs/latest/ug/encryption.html
# custom:
#   avd_id: AVD-AWS-0194
#   provider: aws
#   service: efs
#   severity: HIGH
#   short_code: enable-at-rest-encryption
#   recommended_action: "Encryption of data at rest can only be enabled during file system creation. Encryption of data in transit is configured when mounting your file system. 1. Backup your data in not encrypted efs 2. Recreate the EFS and select \'Enable encryption of data at rest\'"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.efs.aws0193

deny[res] {
	fs := input.aws.efs.filesystems[_]
	not fs.encrypted.value
	res := result.new("File system is not encrypted.", fs.encrypted)
}