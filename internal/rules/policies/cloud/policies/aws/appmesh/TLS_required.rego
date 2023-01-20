# METADATA
# title: "App Mesh TLS Required"
# description: "Ensure that AWS App Mesh virtual gateway listeners only accepts TLS enabled connections."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/app-mesh/latest/APIReference/API_ListenerTls.html
# custom:
#   avd_id: AVD-AWS-0338
#   provider: aws
#   service: appmesh
#   severity: LOW
#   short_code: TLS_requird
#   recommended_action: "Restrict AWS App Mesh virtual gateway listeners to accept only TLS enabled connections."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.appmesh.aws0338

deny[res] {
	mesh := input.aws.appmesh.meshes[_]
    VG := mesh.virtualgateways[_]
    found := [listener | listener = VG.spec.listeners[_]; listener.tls.mode.value != "STRICT"]
    count(found) != 0
	res := result.new("App Mesh virtual gateway listeners does not restrict TLS enabled connections", VG)
}
