# METADATA
# title: "'yum clean all' missing"
# description: "You should use 'yum clean all' after using a 'yum install' command to clean package cached data and reduce image size."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
# custom:
#   id: DS015
#   avd_id: AVD-DS-0015
#   severity: HIGH
#   short_code: purge-yum-package-cache
#   recommended_action: "Add 'yum clean all' to Dockerfile"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS015

import data.lib.docker

get_yum[output] {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match("yum (-[a-zA-Z]+ *)*install", arg)

	not contains_clean_after_yum(arg)
	output := {
		"cmd": run,
		"arg": arg,
	}
}

deny[res] {
	output := get_yum[_]
	msg := sprintf("'yum clean all' is missed: %s", [output.arg])
	res := result.new(msg, output.cmd)
}

contains_clean_after_yum(cmd) {
	yum_commands := regex.find_n("(yum (-[a-zA-Z]+ *)*install)|(yum clean all)", cmd, -1)

	yum_commands[count(yum_commands) - 1] == "yum clean all"
}
