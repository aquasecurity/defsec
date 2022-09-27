# METADATA
# title: "Selector usage in network policies"
# description: "ensure that network policies selectors are applied to pods or namespaces to restricted ingress and egress traffic within the pod network"
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV038
#   avd_id: AVD-KSV-0038
#   severity: MEDIUM
#   short_code: selector-usage-in-network-policies
#   recommended_action: "create network policies and ensure that pods are selected using the podSelector and/or the namespaceSelector options"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV038

import data.lib.kubernetes
import data.lib.utils

hasSelector(spec) {
	kubernetes.has_field(spec, "podSelector")
	kubernetes.has_field(spec.podSelector, "matchLabels")
}

hasSelector(spec) {
	kubernetes.has_field(spec, "namespaceSelector")
}

hasSelector(spec) {
	kubernetes.has_field(spec, "podSelector")
}

hasSelector(spec) {
	kubernetes.has_field(spec, "ingress")
	kubernetes.has_field(spec.ingress[_], "from")
	kubernetes.has_field(spec.ingress[_].from[_], "namespaceSelector")
}

hasSelector(spec) {
	kubernetes.has_field(spec, "ingress")
	kubernetes.has_field(spec.ingress[_], "from")
	kubernetes.has_field(spec.ingress[_].from[_], "podSelector")
}

hasSelector(spec) {
	kubernetes.has_field(spec, "egress")
	kubernetes.has_field(spec.egress[_], "to")
	kubernetes.has_field(spec.egress[_].to[_], "podSelector")
}

hasSelector(spec) {
	kubernetes.has_field(spec, "egress")
	kubernetes.has_field(spec.egress[_], "to")
	kubernetes.has_field(spec.egress[_].to[_], "namespaceSelector")
}

hasSelector(spec) {
	kubernetes.spec.podSelector == {}
	contains(input.spec.policyType, "Egress")
}

hasSelector(spec) {
	kubernetes.spec.podSelector == {}
	contains(input.spec.policyType, "Ingress")
}

contains(arr, elem) {
	arr[_] = elem
}

deny[res] {
	lower(kubernetes.kind) == "networkpolicy"
	not hasSelector(input.spec)
	msg := "Network policy should uses podSelector and/or the namespaceSelector to restrict ingress and egress traffic within the Pod network"
	res := result.new(msg, input.spec)
}
