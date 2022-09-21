# METADATA
# title: ADD instead of COPY
# description: You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.
# scope: package
# related_resources:
# - https://docs.docker.com/engine/reference/builder/#add
# schemas:
# - input: schema["input"]
# custom:
#   id: DS005
#   avd_id: AVD-DS-0005
#   severity: LOW
#   short_code: use-copy-over-add
#   recommended_action: Use COPY instead of ADD
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS005

import data.lib.docker

get_add[output] {
	add := docker.add[_]
	args := concat(" ", add.Value)

	not contains(args, ".tar")
	output := {
		"args": args,
		"cmd": add,
	}
}

deny[res] {
	output := get_add[_]
	msg := sprintf("Consider using 'COPY %s' command instead of 'ADD %s'", [output.args, output.args])
	res := docker.result(msg, output.cmd)
}
