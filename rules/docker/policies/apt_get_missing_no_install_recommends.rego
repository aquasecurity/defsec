# METADATA
# title: "'apt-get' missing '--no-install-recommends'"
# description: "'apt-get' install should use '--no-install-recommends' to minimize image size."
# scope: package
# related_resources:
# - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
# schemas:
# - input: schema["dockerfile"]
# custom:
#   schema_version: 1
#   id: DS029
#   avd_id: AVD-DS-0029
#   severity: HIGH
#   short_code: use-apt-no-install-recommends
#   recommended_action: "Add '--no-install-recommends' flag to 'apt-get'"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS029

import data.lib.docker

deny[res] {
	output := get_apt_get[_]
	msg := sprintf("'--no-install-recommends' flag is missed: '%s'", [output.arg])
	res := result.new(msg, output.cmd)
}

get_apt_get[output] {
	run = docker.run[_]

	count(run.Value) == 1
	arg := run.Value[0]

	is_apt_get(arg)

	not includes_no_install_recommends(arg)

	output := {
		"arg": arg,
		"cmd": run,
	}
}

# checking json array
get_apt_get[output] {
	run = docker.run[_]

	count(run.Value) > 1

	arg := concat(" ", run.Value)

	is_apt_get(arg)

	not includes_no_install_recommends(arg)

	output := {
		"arg": arg,
		"cmd": run,
	}
}

is_apt_get(command) {
	regex.match("apt-get (-(-)?[a-zA-Z]+ *)*install(-(-)?[a-zA-Z]+ *)*", command)
}

no_install_flag := `--no-install-recommends`

optional_not_related_flags := `\s*(-(-)?[a-zA-Z]+\s*)*`

combined_flags := sprintf(`%s%s%s`, [optional_not_related_flags, no_install_flag, optional_not_related_flags])

# flags before command
includes_no_install_recommends(command) {
	install_regexp := sprintf(`apt-get%sinstall`, [combined_flags])
	regex.match(install_regexp, command)
}

# flags behind command
includes_no_install_recommends(command) {
	install_regexp := sprintf(`apt-get%sinstall%s`, [optional_not_related_flags, combined_flags])
	regex.match(install_regexp, command)
}
