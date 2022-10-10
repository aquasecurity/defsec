# METADATA
# title: "Exposed port out of range"
# description: "UNIX ports outside the range 0-65535 are exposed."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://docs.docker.com/engine/reference/builder/#expose
# custom:
#   id: DS008
#   avd_id: AVD-DS-0008
#   severity: CRITICAL
#   short_code: port-out-of-range
#   recommended_action: "Use port number within range"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS008

import data.lib.docker

invalid_ports[output] {
	expose := docker.expose[_]
	port := to_number(split(expose.Value[_], "/")[0])
	port > 65535
	output := {
		"port": port,
		"cmd": expose,
	}
}

deny[res] {
	output := invalid_ports[_]
	msg := sprintf("'EXPOSE' contains port which is out of range [0, 65535]: %d", [output.port])
	res := result.new(msg, output.cmd)
}
