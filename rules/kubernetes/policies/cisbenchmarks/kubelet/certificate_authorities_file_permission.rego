# METADATA
# title: "Ensure that the certificate authorities file permissions are set to 600 or more restrictive"
# description: "Ensure that the certificate authorities file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0075
#   avd_id: AVD-KCV-0075
#   severity: CRITICAL
#   short_code: ensure-certificate-authorities-file-permissions-600-or-more-restrictive.
#   recommended_action: "Change the certificate authorities file permissions to 600 or more restrictive if exist"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0075

import data.lib.kubernetes

types := ["master", "worker"]

validate_certificate_authorities_file_permission(sp) := {"certificateAuthoritiesFilePermissions": violation} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {permission | permission = sp.info.certificateAuthoritiesFilePermissions.values[_]; permission > 600}
	count(violation) > 0
}

deny[res] {
	output := validate_certificate_authorities_file_permission(input)
	msg := "Ensure that the certificate authorities file permissions are set to 600 or more restrictive"
	res := result.new(msg, output)
}
