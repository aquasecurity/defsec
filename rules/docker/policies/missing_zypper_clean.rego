# METADATA
# title: "'zypper clean' missing"
# description: "The layer and image size should be reduced by deleting unneeded caches after running zypper."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
# custom:
#   id: DS020
#   avd_id: AVD-DS-0020
#   severity: HIGH
#   short_code: purge-zipper-cache
#   recommended_action: "Add 'zypper clean' to Dockerfile"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS020

import data.lib.docker

install_regex := `(zypper in)|(zypper remove)|(zypper rm)|(zypper source-install)|(zypper si)|(zypper patch)|(zypper (-(-)?[a-zA-Z]+ *)*install)`

zypper_regex = sprintf("%s|(zypper clean)|(zypper cc)", [install_regex])

get_zypper[output] {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match(install_regex, arg)

	not contains_zipper_clean(arg)
	output := {
		"arg": arg,
		"cmd": run,
	}
}

deny[res] {
	output := get_zypper[_]
	msg := sprintf("'zypper clean' is missed: '%s'", [output.arg])
	res := result.new(msg, output.cmd)
}

contains_zipper_clean(cmd) {
	zypper_commands := regex.find_n(zypper_regex, cmd, -1)

	is_zypper_clean(zypper_commands[count(zypper_commands) - 1])
}

is_zypper_clean(cmd) {
	cmd == "zypper clean"
}

is_zypper_clean(cmd) {
	cmd == "zypper cc"
}
