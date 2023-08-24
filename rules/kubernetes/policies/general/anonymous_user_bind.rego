# METADATA
# title: "Anonymous user access binding"
# description: "Binding to anonymous user to any clusterrole or role is a security risk."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://blog.aquasec.com/kubernetes-exposed-one-yaml-away-from-disaster
# custom:
#   id: KSV122
#   avd_id: AVD-KSV-0122
#   severity: CRITICAL
#   short_code: no-anonymous-user-bind
#   recommended_action: "Remove anonymous user binding from clusterrolebinding or rolebinding."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: rolebinding
#         - kind: clusterrolebinding

package appshield.kubernetes.KSV122

import data.lib.kubernetes

readRoleRefs := ["system:unauthenticated", "system:anonymous"]

readKinds := ["RoleBinding", "ClusterRolebinding"]

anonymousUserBind(roleBinding) {
	kubernetes.kind == readKinds[_]
	kubernetes.object.subjects[_].name == readRoleRefs[_]
}

deny[res] {
	anonymousUserBind(input)
	msg := kubernetes.format(sprintf("%s '%s' should not bind to roles %s", [kubernetes.kind, kubernetes.name, readRoleRefs]))
	res := result.new(msg, input.metadata)
}