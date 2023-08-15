# METADATA
# title: "Compute Boot Diagnostics"
# description: "Boot diagnostics enabled or not"
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
# custom:
#   avd_id: AVD-AZURE-0040
#   provider: azure
#   service: compute
#   severity: HIGH
#   short_code: boot_diagnostics_enabled
#   recommended_action: "recommended_action"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: compute
#           provider: azure

package builtin.azure.compute.azure0040

deny [res] {
     list := input.azure.compute.virtualmachinelist
     vm := list.value[_]
     vm.properties.diagnosticsprofile.bootdiagnostics.enabled.value
     res := result.new("enabled", vm.properties.diagnosticsprofile.bootdiagnostics.enabled)
}