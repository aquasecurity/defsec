# METADATA
# title: "Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive"
# description: "Ensure that the scheduler pod specification file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0052
#   avd_id: AVD-KCV-0052
#   severity: HIGH
#   short_code: ensure-scheduler-pod-specification-file-permissions-set-600-or-more-restrictive
#   recommended_action: "Change the scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml permissions of 600 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0052

import data.lib.kubernetes

validate_spec_permission(sp) := {"kubeSchedulerSpecFilePermission": permission} {
	sp.kind == "Nodeinfo"
	sp.type == "master"
	permission := sp.info.kubeSchedulerSpecFilePermission[_]
	permission > 600
}

deny[res] {
	output := validate_spec_permission(input)
	msg := "Ensure that the scheduler specification file permissions is set to 600 or more restrictive"
	res := result.new(msg, output)
}
