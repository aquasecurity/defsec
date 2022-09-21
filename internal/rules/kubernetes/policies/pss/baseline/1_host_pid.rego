# METADATA
# title: "Access to host PID"
# description: "Sharing the host’s PID namespace allows visibility on host processes, potentially leaking information such as environment variables and configuration."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV010
#   avd_id: AVD-KSV-0010
#   severity: HIGH
#   short_code: no-host-pid
#   recommended_action: "Do not set 'spec.template.spec.hostPID' to true."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV010

import data.lib.kubernetes
import data.lib.result

default failHostPID = false

# failHostPID is true if spec.hostPID is set to true (on all controllers)
failHostPID {
	kubernetes.host_pids[_] == true
}

deny[res] {
	failHostPID
	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.spec.hostPID' to true", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
