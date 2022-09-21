# METADATA
# title: "RUN using 'sudo'"
# description: "Avoid using 'RUN' with 'sudo' commands, as it can lead to unpredictable behavior."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: DS010
#   avd_id: AVD-DS-0010
#   severity: CRITICAL
#   short_code: no-sudo-run
#   recommended_action: "Don't use sudo"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS010

import data.lib.docker

has_sudo(commands) {
	parts = split(commands, "&&")

	instruction := parts[_]
	regex.match(`^\s*sudo`, instruction)
}

get_sudo[run] {
	run = docker.run[_]
	count(run.Value) == 1
	arg := run.Value[0]
	has_sudo(arg)
}

deny[res] {
	cmd := get_sudo[_]
	msg := "Using 'sudo' in Dockerfile should be avoided"
	res := docker.result(msg, cmd)
}
