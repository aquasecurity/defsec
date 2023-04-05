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
#   short_code: dnf_dont_install_docs_in_docker
#   recommended_action: "Use '--nodocs' to 'dnf install' to Dockerfile"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS028

import data.lib.docker

get_dnf[output] {
	run := docker.run[_]
	arg := run.Value[0]

	# try to find all combinations of microdnf install, microdnf install and dnf install
	regex.match("dnf (-(-)?[a-zA-Z]+ *)*install(-(-)?[a-zA-Z]+ *)*", arg)

	not contains_nodocs(arg)

	output := {
		"cmd": run,
		"arg": arg,
	}
}

deny[res] {
	output := get_dnf[_]
	msg := sprintf("'--nodocs' is missing for dnf package installation: %s: ", [output.arg])
	res := result.new(msg, output.cmd)
}

contains_nodocs(cmd) {
	split(cmd, " ")[_] == "--nodocs"
}
