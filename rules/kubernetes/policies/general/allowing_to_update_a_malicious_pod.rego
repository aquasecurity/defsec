# METADATA
# title: "Manage Kubernetes workloads and pods"
# description: "Depending on the policies enforced by the admission controller, this permission ranges from the ability to steal compute (crypto) by running workloads or allowing for creating workloads that escape to the node as root and escalation to cluster-admin."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV048
#   avd_id: AVD-KSV-0048
#   severity: MEDIUM
#   short_code: deny-create-update-malicious-pod
#   recommended_action: "Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'"
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
