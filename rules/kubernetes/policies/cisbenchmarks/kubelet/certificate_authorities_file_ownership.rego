# METADATA
# title: "Ensure that the client certificate authorities file ownership is set to root:root"
# description: "Ensure that the certificate authorities file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0076
#   avd_id: AVD-KCV-0076
#   severity: CRITICAL
#   short_code: ensure-certificate_authorities-ownership-set-root:root
#   recommended_action: "Change the certificate authorities file ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0076

import data.lib.kubernetes

types := ["master", "worker"]

validate_certificate_authorities_ownership(sp) := {"certificateAuthoritiesFileOwnership": violation} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {ownership | ownership = sp.info.certificateAuthoritiesFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny[res] {
	output := validate_certificate_authorities_ownership(input)
	msg := "Ensure that the certificate authorities file ownership is set to root:root."
	res := result.new(msg, output)
}
