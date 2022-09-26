# METADATA
# title: "Port 22 exposed"
# description: "Exposing port 22 might allow users to SSH into the container."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: DS004
#   avd_id: AVD-DS-0004
#   severity: MEDIUM
#   short_code: no-ssh-port
#   recommended_action: "Remove 'EXPOSE 22' statement from the Dockerfile"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS004

import data.lib.docker

# deny_list contains the port numbers which needs to be denied.
denied_ports := ["22", "22/tcp", "22/udp"]

# fail_port_check is true if the Dockerfile contains an expose statement for value 22
fail_port_check[expose] {
	expose := docker.expose[_]
	expose.Value[_] == denied_ports[_]
}

deny[res] {
	cmd := fail_port_check[_]
	msg := "Port 22 should not be exposed in Dockerfile"
	res := result.new(msg, cmd)
}
