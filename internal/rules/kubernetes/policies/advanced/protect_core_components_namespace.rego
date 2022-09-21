# METADATA
# title: "User Pods should not be placed in kube-system namespace"
# description: "ensure that User pods are not placed in kube-system namespace"
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV037
#   avd_id: AVD-KSV-0037
#   severity: MEDIUM
#   short_code: no-user-pods-in-system-namespace
#   recommended_action: "Deploy the use pods into a designated namespace which is not kube-system."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV037

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

systemNamespaceInUse(metadata, spec) {
	kubernetes.namespace == "kube-system"
	not core_component(metadata, spec)
}

core_component(metadata, spec) {
	kubernetes.has_field(metadata.labels, "tier")
	metadata.labels.tier == "control-plane"
	kubernetes.has_field(spec, "priorityClassName")
	spec.priorityClassName == "system-node-critical"
	kubernetes.has_field(metadata.labels, "component")
	coreComponentLabels := ["kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler"]
	metadata.labels.component = coreComponentLabels[_]
}

deny[res] {
	systemNamespaceInUse(input.metadata, input.spec)
	msg := sprintf("%s '%s' should not be set with 'kube-system' namespace", [kubernetes.kind, kubernetes.name])
	res := result.new(msg, input.spec)
}
