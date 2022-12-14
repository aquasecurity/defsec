# METADATA
# title: "The default namespace should not be used"
# description: "ensure that default namespace should not be used"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
# custom:
#   id: KSV110
#   avd_id: AVD-KSV-0110
#   severity: MEDIUM
#   short_code: default-namespace-should-not-be-inuse
#   recommended_action: "namespaces are created to allow for appropriate segregation of Kubernetes resources and that all new resources are created in a specific namespace"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV110

import data.lib.kubernetes
import data.lib.utils

workloads := ["pod", "replicaset", "replicationcontroller", "statefulset", "daemonset", "cronjob", "job"]

defaultNamespaceInUse(kubeInput) {
	lower(kubeInput.kind) == workloads[_]
	kubeInput.metadata.namespace == "default"
}

deny[res] {
	defaultNamespaceInUse(input)
	msg := sprintf("%s '%s' should not be set with 'default' namespace", [input.kind, input.metadata.name])
	res := result.new(msg, input.spec)
}
