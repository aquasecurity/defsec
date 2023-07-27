# METADATA
# title: "Workloads in the default namespace"
# description: "ensure that default namespace should not be used"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
# custom:
#   id: KSV110
#   avd_id: AVD-KSV-0110
#   severity: LOW
#   short_code: default-namespace-should-not-be-used
#   recommended_action: "Ensure that namespaces are created to allow for appropriate segregation of Kubernetes resources and that all new resources are created in a specific namespace."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV110

import data.lib.kubernetes

default defaultNamespaceInUse = false

allowedKinds := ["pod", "replicaset", "replicationcontroller", "deployment", "statefulset", "daemonset", "cronjob", "job"]

defaultNamespaceInUse {
	kubernetes.namespace == "default"
	lower(kubernetes.kind) == allowedKinds[_]
}

deny[res] {
	defaultNamespaceInUse
	msg := kubernetes.format(sprintf("%s %s in %s namespace should set metadata.namespace to a non-default namespace", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, input.metadata.namespace)
}
