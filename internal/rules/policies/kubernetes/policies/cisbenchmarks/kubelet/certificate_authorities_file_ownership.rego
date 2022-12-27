# METADATA
# title: "Ensure that the certificate authorities file permissions are set to 600 or more restrictive"
# description: "Ensure that the certificate authorities file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0076
#   avd_id: AVD-KCV-0076
#   severity: HIGH
#   short_code: ensure-certificate_authorities-ownership-set-root:root
#   recommended_action: "Change the certificate authorities file ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0076

import data.lib.kubernetes

types := ["master", "worker"]

validate_certificate_authorities_ownership(sp) := {"certificateAuthoritiesFileOwnership": ownership} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	ownership := sp.info.certificateAuthoritiesFileOwnership.values[_]
	not ownership == "root:root"
}

deny[res] {
	output := validate_certificate_authorities_ownership(input)
	msg := "Ensure that the certificate authorities file permissions are set to 600 or more restrictive"
	res := result.new(msg, output)
}
