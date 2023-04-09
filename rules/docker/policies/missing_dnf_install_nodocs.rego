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
	run = docker.run[_]

	count(run.Value) == 1
	arg := run.Value[0]

	is_dnf(arg)

	not includes_assume_yes(arg)

	output := {
		"arg": arg,
		"cmd": run,
	}
}

# checking json array
get_dnf[output] {
	run = docker.run[_]

	count(run.Value) > 1

	arg := concat(" ", run.Value)

	is_dnf(arg)

	not includes_nodocs(arg)

	output := {
		"arg": arg,
		"cmd": run,
	}
}

deny[res] {
	output := get_dnf[_]
	msg := sprintf("'--nodocs' is missing for dnf package installation: %s: ", [output.arg])
	res := result.new(msg, output.cmd)
}

nodocs_flags := `--nodocs`

optional_not_related_flags := `\s*(-(-)?[a-zA-Z]+\s*)*`

combined_flags := sprintf(`%s%s%s`, [optional_not_related_flags, nodocs_flags, optional_not_related_flags])

dnf_install_regex := `(install)|(in)|(reinstall)|(rei)|(install-n)|(install-na)|(install-nevra)`

# dnf
is_dnf(command) {
	regex.match(sprintf("dnf%s%s%s", combined_flags, dnf_install_regex, combined_flags), arg)
}

# microdnf
is_dnf(command) {
	regex.match(sprintf("microdnf%s(install|reinstall)%s", combined_flags, combined_flags), command)
}

# flags before command
includes_nodocs(command) {
	install_regexp := sprintf(`%s`, [combined_flags])
	regex.match(install_regexp, command)
}

includes_nodocs(command) {
	install_regexp := sprintf(`%s`, [combined_flags])
	regex.match(install_regexp, command)
}

# flags behind command
includes_nodocs(command) {
	install_regexp := sprintf(`%s%s`, [optional_not_related_flags, combined_flags])
	regex.match(install_regexp, command)
}
