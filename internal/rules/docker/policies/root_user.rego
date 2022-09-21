# METADATA
# title: "Image user should not be 'root'"
# description: "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: DS002
#   avd_id: AVD-DS-0002
#   severity: HIGH
#   short_code: least-privilege-user
#   recommended_action: "Add 'USER <non root user name>' line to the Dockerfile"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS002

import data.lib.docker

# get_user returns all the usernames from
# the USER command.
get_user[username] {
	user := docker.user[_]
	username := user.Value[_]
}

# fail_user_count is true if there is no USER command.
fail_user_count {
	count(get_user) < 1
}

# fail_last_user_root is true if the last USER command
# value is "root"
fail_last_user_root[lastUser] {
	users := [user | user := docker.user[_]; true]
	lastUser := users[count(users) - 1]
	lastUser.Value[0] == "root"
}

deny[res] {
	fail_user_count
	msg := "Specify at least 1 USER command in Dockerfile with non-root user as argument"
	res := docker.result(msg, {})
}

deny[res] {
	cmd := fail_last_user_root[_]
	msg := "Last USER command in Dockerfile should not be 'root'"
	res := docker.result(msg, cmd)
}
