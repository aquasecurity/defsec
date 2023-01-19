# METADATA
# title: "'apk add' is missing '--no-cache'"
# description: "You should use 'apk add' with '--no-cache' to clean package cached data and reduce image size."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://github.com/gliderlabs/docker-alpine/blob/master/docs/usage.md#disabling-cache
# custom:
#   id: DS025
#   avd_id: AVD-DS-0025
#   severity: HIGH
#   short_code: purge-apk-package-cache
#   recommended_action: "Add '--no-cache' to 'apk add' in Dockerfile"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS025

import data.lib.docker

get_apk[output] {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match("apk (-[a-zA-Z]+\\s*)*add", arg)

	not contains_no_cache(arg)

	output := {
		"cmd": run,
		"arg": arg,
	}
}

deny[res] {
	output := get_apk[_]
	msg := sprintf("'--no-cache' is missed: %s", [output.arg])
	print(msg)
	res := result.new(msg, output.cmd)
}

contains_no_cache(cmd) {
	split(cmd, " ")[_] == "--no-cache"
}
