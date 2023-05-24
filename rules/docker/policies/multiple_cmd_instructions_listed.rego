# METADATA
# title: "Multiple CMD instructions listed"
# description: "There can only be one CMD instruction in a Dockerfile. If you list more than one CMD then only the last CMD will take effect."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/engine/reference/builder/#cmd
# custom:
#   id: DS016
#   avd_id: AVD-DS-0016
#   severity: HIGH
#   short_code: only-one-cmd
#   recommended_action: "Dockerfile should only have one CMD instruction. Remove all the other CMD instructions"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS016

import data.lib.docker

deny[res] {
	cmds := docker.stage_cmd[name]
	cnt := count(cmds)
	cnt > 1
	msg := sprintf("There are %d duplicate CMD instructions for stage", [cnt])
	res := result.new(msg, cmds[1])
}
