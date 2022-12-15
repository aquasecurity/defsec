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
#   severity: LOW
#   short_code: default-namespace-should-not-be-used
#   recommended_action: "Ensure that namespaces are created to allow for appropriate segregation of Kubernetes resources and that all new resources are created in a specific namespace."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV110

import data.lib.kubernetes

defaultNamespaceInUse {
	kubernetes.namespace == "default"
}

deny[res] {
	defaultNamespaceInUse
	msg := sprintf("%s '%s' should not be set with 'default' namespace", [kubernetes.kind, kubernetes.name])
	res := result.new(msg, input.metadata.namespace)
}
