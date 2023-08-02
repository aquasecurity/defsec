# METADATA
# title: "Manage Kubernetes workloads and pods"
# description: "Check whether role permits update/create of a malicious pod"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV048
#   avd_id: AVD-KSV-0048
#   severity: HIGH
#   short_code: deny-create-update-malicious-pod
#   recommended_action: "Create a role which does not permit update/create of a malicious pod"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV048

import data.lib.kubernetes
import data.lib.utils

workloads := ["pods", "deployments", "jobs", "cronjobs", "statefulsets", "daemonsets", "replicasets", "replicationcontrollers"]

changeVerbs := ["create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

update_malicious_pod[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == workloads[_]
	input.rules[ru].verbs[v] == changeVerbs[_]
}

deny[res] {
	badRule := update_malicious_pod[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s", [kubernetes.kind, kubernetes.name, workloads, changeVerbs]))
	res := result.new(msg, badRule)
}
