# METADATA
# title: "Multiple HEALTHCHECK defined"
# description: "Providing more than one HEALTHCHECK instruction per stage is confusing and error-prone."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/engine/reference/builder/#healthcheck
# custom:
#   id: DS023
#   avd_id: AVD-DS-0023
#   severity: MEDIUM
#   short_code: only-one-healthcheck
#   recommended_action: "One HEALTHCHECK instruction must remain in Dockerfile. Remove all other instructions."
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS023

import data.lib.docker

deny[res] {
	healthchecks := docker.stage_healthcheck[name]
	cnt := count(healthchecks)
	cnt > 1
	msg := sprintf("There are %d duplicate HEALTHCHECK instructions in the stage", [cnt])
	res := result.new(msg, healthchecks[1])
}
