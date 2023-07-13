# METADATA
# title: "'RUN <package-manager> update' instruction alone"
# description: "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
# custom:
#   id: DS017
#   avd_id: AVD-DS-0017
#   severity: HIGH
#   short_code: no-orphan-package-update
#   recommended_action: "Combine '<package-manager> update' and '<package-manager> install' instructions to single one"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS017

import data.lib.docker

deny[res] {
	run := docker.run[_]

	command = concat(" ", run.Value)

  is_package_manager(command)
	is_valid_update(command)
	not update_followed_by_install(command)

	msg := "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement."
	res := result.new(msg, run)
}

package_manager_regex := `(apk)|(apt-get)|(yum)`

is_package_manager(command) {
  regex.match(package_manager_regex, command)
}

update_regex := `( update)|( check-update)`
is_valid_update(command) {
  regex.match(update_regex, command)
}

update_followed_by_install(command) {
	command_list = [
		"upgrade",
		"install",
		"source-install",
		"reinstall",
		"groupinstall",
		"localinstall",
		"apk add",
	]

	update := indexof(command, "update")
	update != -1

	install := indexof(command, command_list[_])
	install != -1

	update < install
}
