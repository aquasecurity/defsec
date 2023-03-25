# METADATA
# title: "'microdnf clean all' missing"
# description: "Cached package data should be cleaned after installation to reduce image size."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
# custom:
#   id: DS025
#   avd_id: AVD-DS-0025
#   severity: HIGH
#   short_code: purge-microdnf-package-cache
#   recommended_action: "Add 'microdnf clean all' to Dockerfile"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS025

import data.lib.docker

install_regex := `(microdnf install)|(microdnf reinstall)`

microdnf_regex = sprintf("%s|(microdnf clean all)", [install_regex])

get_dnf[output] {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match(install_regex, arg)

	not contains_clean_after_dnf(arg)
	output := {
		"arg": arg,
		"cmd": run,
	}
}

deny[res] {
	output := get_dnf[_]
	msg := sprintf("'microdnf clean all' is missed: %s", [output.arg])
	res := result.new(msg, output.cmd)
}

contains_clean_after_dnf(cmd) {
	dnf_commands := regex.find_n(microdnf_regex, cmd, -1)

	dnf_commands[count(dnf_commands) - 1] == "microdnf clean all"
}
