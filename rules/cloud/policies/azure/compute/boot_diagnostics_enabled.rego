# METADATA
# title: "Virtual Machine Boot Diagnostics Enabled"
# description: "Ensures that the VM boot diagnostics is enabled for virtual machines"
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.microsoft.com/en-us/azure/virtual-machines/boot-diagnostics
# custom:
#   avd_id: AVD-AZURE-0040
#   provider: azure
#   service: compute
#   severity: HIGH
#   short_code: boot_diagnostics_enabled
#   recommended_action: "Enable boot diagnostics for all virtual machines.'"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: compute
#           provider: azure

package builtin.azure.compute.azure0040

deny [res] {
     list := input.azure.compute.virtualmachinelist[_]
     not list.properties.diagnosticsprofile.bootdiagnostics.enabled.value
     res := result.new("Virtual machine does not have boot diagnostics enabled", list.properties.diagnosticsprofile.bootdiagnostics.enabled)
}