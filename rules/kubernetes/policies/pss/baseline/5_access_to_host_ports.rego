# METADATA
# title: "Access to host ports"
# description: "According to pod security standard 'Host Ports', hostPorts should be disallowed, or at minimum restricted to a known list."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV024
#   avd_id: AVD-KSV-0024
#   severity: HIGH
#   short_code: no-host-port-access
#   recommended_action: "Do not set spec.containers[*].ports[*].hostPort and spec.initContainers[*].ports[*].hostPort."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: pod
#         - kind: replicaset
#         - kind: replicationcontroller
#         - kind: deployment
#         - kind: statefulset
#         - kind: daemonset
#         - kind: cronjob
#         - kind: job
package builtin.kubernetes.KSV024

import data.lib.kubernetes

default failHostPorts = false

# Add allowed host ports to this set
allowed_host_ports = set()

# getContainersWithDisallowedHostPorts returns a list of containers which have
# host ports not included in the allowed host port list
getContainersWithDisallowedHostPorts[container] {
	allContainers := kubernetes.containers[_]
	set_host_ports := {port | port := allContainers.ports[_].hostPort}
	host_ports_not_allowed := set_host_ports - allowed_host_ports
	count(host_ports_not_allowed) > 0
	container := allContainers.name
}

# host_ports_msg is a string of allowed host ports to be print as part of deny message
host_ports_msg = "" {
	count(allowed_host_ports) == 0
} else = msg {
	msg := sprintf(" or set it to the following allowed values: %s", [concat(", ", allowed_host_ports)])
}

# Get all containers which don't include 'ALL' in security.capabilities.drop
getContainersWitNohDisallowedHostPorts[container] {
	container := kubernetes.containers[_]
	not getContainersWithDisallowedHostPorts[container]
}

deny[res] {
	output := getContainersWitNohDisallowedHostPorts[_]
	msg := sprintf("Container '%s' of %s '%s' should not set host ports, 'ports[*].hostPort'%s", [getContainersWithDisallowedHostPorts[_], kubernetes.kind, kubernetes.name, host_ports_msg])
	res := result.new(msg, output)
}
