# METADATA
# title: "'apk add' is missing '--no-cache'"
# description: "You should use 'apk add' with '--no-cache' to clean package cached data and reduce image size."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://github.com/gliderlabs/docker-alpine/blob/master/docs/usage.md#disabling-cache
# custom:
#   id: DS025
#   avd_id: AVD-DS-0025
#   severity: HIGH

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

install_regex := `(dnf install)|(dnf in)|(dnf reinstall)|(dnf rei)|(dnf install-n)|(dnf install-na)|(dnf install-nevra)|(microdnf install)|(microdnf reinstall)`

# better regex
dnf_regex = sprintf("%s", [install_regex])

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
	msg := sprintf("'dnf clean all' is missed: %s", [output.arg])
	res := result.new(msg, output.cmd)
}

contains_clean_after_dnf(cmd) {
	dnf_commands := regex.find_n(dnf_regex, cmd, -1)

	dnf_commands[count(dnf_commands) - 1] == "dnf clean all"
}
