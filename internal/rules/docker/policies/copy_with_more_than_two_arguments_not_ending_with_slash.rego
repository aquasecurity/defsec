# METADATA
# title: "COPY with more than two arguments not ending with slash"
# description: "When a COPY command has more than two arguments, the last one should end with a slash."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: DS011
#   avd_id: AVD-DS-0011
#   severity: CRITICAL
#   short_code: use-slash-for-copy-args
#   recommended_action: "Add slash to last COPY argument"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS011

import data.lib.docker

get_copy_arg[output] {
	copy := docker.copy[_]

	cnt := count(copy.Value)
	cnt > 2

	arg := copy.Value[cnt - 1]
	not endswith(arg, "/")
	output := {
		"arg": arg,
		"cmd": copy,
	}
}

deny[res] {
	output := get_copy_arg[_]
	msg := sprintf("Slash is expected at the end of COPY command argument '%s'", [output.arg])
	res := docker.result(msg, output.cmd)
}
