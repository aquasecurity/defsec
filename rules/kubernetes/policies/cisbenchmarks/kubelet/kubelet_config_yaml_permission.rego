# METADATA
# title: "If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive"
# description: "Ensure that if the kubelet refers to a configuration file with the --config argument, that file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0077
#   avd_id: AVD-KCV-0077
#   severity: HIGH
#   short_code: ensure-kubelet-config.yaml--permissions-600-or-more-restrictive.
#   recommended_action: "Change the kubelet config yaml permissions to 600 or more restrictive if exist"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0077

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_config_yaml_permission(sp) := {"kubeletConfigYamlConfigurationFilePermission": violation} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletConfigYamlConfigurationFilePermission) > 0
	violation := {permission | permission = sp.info.kubeletConfigYamlConfigurationFilePermission.values[_]; permission > 600}
	count(violation) > 0
}

deny[res] {
	output := validate_kubelet_config_yaml_permission(input)
	msg := "Ensure that if the kubelet refers to a configuration file with the --config argument, that file has permissions of 600 or more restrictive."
	res := result.new(msg, output)
}
