# METADATA
# title: "hostPath volume mounted with docker.sock"
# description: "Mounting docker.sock from the host can give the container full root access to the host."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://kubesec.io/basics/spec-volumes-hostpath-path-var-run-docker-sock/
# custom:
#   id: KSV006
#   avd_id: AVD-KSV-0006
#   severity: HIGH
#   short_code: no-docker-sock-mount
#   recommended_action: "Do not specify /var/run/docker.socket in 'spec.template.volumes.hostPath.path'."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV006

import data.lib.kubernetes

name = input.metadata.name

default checkDockerSocket = false

# checkDockerSocket is true if volumes.hostPath.path is set to /var/run/docker.sock
# and is false if volumes.hostPath is set to some other path or not set.
checkDockerSocket {
	volumes := kubernetes.volumes
	volumes[_].hostPath.path == "/var/run/docker.sock"
}

deny[res] {
	checkDockerSocket
	msg := kubernetes.format(sprintf("%s '%s' should not specify '/var/run/docker.socker' in 'spec.template.volumes.hostPath.path'", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
