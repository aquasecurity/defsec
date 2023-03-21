# METADATA
# title: "WORKDIR path not absolute"
# description: "For clarity and reliability, you should always use absolute paths for your WORKDIR."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir
# custom:
#   id: DS009
#   avd_id: AVD-DS-0009
#   severity: HIGH
#   short_code: user-absolute-workdir
#   recommended_action: "Use absolute paths for your WORKDIR"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS009

import data.lib.docker

get_work_dir[output] {
	workdir := docker.workdir[_]
	arg := workdir.Value[0]

	not regex.match("^[\"']?(/[A-z0-9-_+]*)|([A-z0-9-_+]:\\\\.*)|(\\$[{}A-z0-9-_+].*)", arg)
	output := {
		"cmd": workdir,
		"arg": arg,
	}
}

deny[res] {
	output := get_work_dir[_]
	msg := sprintf("WORKDIR path '%s' should be absolute", [output.arg])
	res := result.new(msg, output.cmd)
}
