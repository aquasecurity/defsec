package builtin.kubernetes.KSV038

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV038",
	"avd_id": "AVD-KSV-0038",
	"title": "Selector usage in network policies",
	"short_code": "selector-usage-in-network-policies",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "ensure that network policies selectors are applied to pods or namespaces to restricted ingress and egress traffic within the pod network",
	"recommended_actions": "create network policies and ensure that pods are selected using the podSelector and/or the namespaceSelector options",
	"url": "https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

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
