# METADATA
# title: "Do not allow update/create of a malicious pod"
# description: "Check whether role permits update/create of a malicious pod"
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV048
#   avd_id: AVD-KSV-0048
#   severity: HIGH
#   short_code: deny-create-update-malicious-pod
#   recommended_action: "Create a role which does not permit update/create of a malicious pod"
#   input:
#     selector:
#     - type: rbac
package builtin.kubernetes.KSV048

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

workloads := ["deployments", "daemonsets", "statefulsets", "replicationcontrollers", "replicasets", "jobs", "cronjobs"]

changeVerbs := ["update", "create", "*"]

readKinds := ["Role", "ClusterRole"]

update_malicious_pod[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == workloads[_]
	input.rules[ru].verbs[v] == changeVerbs[_]
}

deny[res] {
	badRule := update_malicious_pod[_]
	msg := "Role permits create/update of a malicious pod"
	res := result.new(msg, badRule)
}
