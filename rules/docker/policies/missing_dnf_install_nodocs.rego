# METADATA
# title: "'(micro)dnf install' is missing '--nodocs'"
# description: "You should use '(micro)dnf install' with '--nodocs' to avoid installing documentation and reduce image size."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# custom:
#   id: DS028
#   avd_id: AVD-DS-0028
#   severity: HIGH
#   short_code: docs_not_needed_in_docker
#   recommended_action: "Use '--nodocs' to 'dnf install' to Dockerfile"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS028

import data.lib.docker

get_dnf[output] {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match("(micro)?dnf (-[a-zA-Z]+\\s*)install(-[a-zA-Z]+\\s*)*", arg)

	not contains_nodocs(arg)

	output := {
		"cmd": run,
		"arg": arg,
	}
}


contains_nodocs(cmd) {
	# contains at any 
	split(cmd, " ")[_] == "--nodocs"
}

deny[res] {
	output := get_dnf[_]
	msg := sprintf("'--no-cache' is missed: %s: ", [output.arg])
	res := result.new(msg, output.cmd)
}
