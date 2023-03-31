# METADATA
# title: "'RUN cd ...' to change directory"
# description: "Use WORKDIR instead of proliferating instructions like 'RUN cd … && do-something', which are hard to read, troubleshoot, and maintain."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir
# custom:
#   id: DS013
#   avd_id: AVD-DS-0013
#   severity: MEDIUM
#   short_code: use-workdir-over-cd
#   recommended_action: "Use WORKDIR to change directory"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS013

import data.lib.docker

get_cd[output] {
	run := docker.run[_]
	parts = regex.split(`\s*&&\s*`, run.Value[_])
	startswith(parts[_], "cd ")
	args := concat(" ", run.Value)
	output := {
		"args": args,
		"cmd": run,
	}
}

deny[res] {
	output := get_cd[_]
	msg := sprintf("RUN should not be used to change directory: '%s'. Use 'WORKDIR' statement instead.", [output.args])
	res := result.new(msg, output.cmd)
}
