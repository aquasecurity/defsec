# METADATA
# title: "Multiple ENTRYPOINT instructions listed"
# description: "There can only be one ENTRYPOINT instruction in a Dockerfile. Only the last ENTRYPOINT instruction in the Dockerfile will have an effect."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://docs.docker.com/engine/reference/builder/#entrypoint
# custom:
#   id: DS007
#   avd_id: AVD-DS-0007
#   severity: CRITICAL
#   short_code: only-one-entrypoint
#   recommended_action: "Remove unnecessary ENTRYPOINT instruction."
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS007

import data.lib.docker

deny[res] {
	entrypoints := docker.stage_entrypoints[name]
	count(entrypoints) > 1
	msg := sprintf("There are %d duplicate ENTRYPOINT instructions for stage '%s'", [count(entrypoints), name])
	res := result.new(msg, entrypoints[1])
}
