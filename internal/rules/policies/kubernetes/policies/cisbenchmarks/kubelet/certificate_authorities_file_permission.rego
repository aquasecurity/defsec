# METADATA
# title: "Ensure that the certificate authorities file permissions are set to 600 or more restrictive"
# description: "Ensure that the certificate authorities file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0075
#   avd_id: AVD-KCV-0075
#   severity: HIGH
#   short_code: ensure-certificate-authorities-file-permissions-600-or-more-restrictive.
#   recommended_action: "Change the certificate authorities file permissions to 600 or more restrictive if exist"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0075

import data.lib.kubernetes

types := ["master", "worker"]

validate_certificate_authorities_file_permission(sp) := {"certificateAuthoritiesFilePermissions": permission} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	permission := sp.info.certificateAuthoritiesFilePermissions.values[_]
	permission > 600
}

deny[res] {
	output := validate_certificate_authorities_file_permission(input)
	msg := "Ensure that the certificate authorities file permissions are set to 600 or more restrictive"
	res := result.new(msg, output)
}
