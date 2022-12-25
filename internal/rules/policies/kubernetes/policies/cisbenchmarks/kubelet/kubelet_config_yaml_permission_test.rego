package builtin.kubernetes.KCV0077

test_validate_kubelet_config_yaml_permission_equal_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletConfigYamlConfigurationFilePermission": {"values": [600]}},
	}

	count(r) == 0
}

test_validate_kublet_config_yaml_permission_lower_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletConfigYamlConfigurationFilePermission": {"values": [500]}},
	}

	count(r) == 0
}

test_validate_kubelet_config_yaml_permission_no_result {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletConfigYamlConfigurationFilePermission": {"values": []}},
	}

	count(r) == 0
}

test_validate_kubelet_config_yaml_permission_higher_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletConfigYamlConfigurationFilePermission": {"values": [700]}},
	}

	count(r) == 1
}
