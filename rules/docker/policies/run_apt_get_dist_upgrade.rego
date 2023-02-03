# METADATA
# title: "'apt-get dist-upgrade' used"
# description: "'apt-get dist-upgrade' upgrades a major version so it doesn't make more sense in Dockerfile."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: DS024
#   avd_id: AVD-DS-0024
#   severity: HIGH
#   short_code: no-dist-upgrade
#   recommended_action: "Just use different image"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS024

import data.lib.docker

get_apt_get_dist_upgrade[run] {
	run := docker.run[_]
	regex.match(`apt-get .* dist-upgrade`, run.Value[0])
}

deny[res] {
	cmd := get_apt_get_dist_upgrade[_]
	msg := "'apt-get dist-upgrade' should not be used in Dockerfile"
	res := result.new(msg, cmd)
}
