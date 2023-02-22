package builtin.kubernetes.KCV0078

test_validate_kubelet_config_yaml_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletConfigYamlConfigurationFileOwnership": {"values": ["root:root"]}},
	}

	count(r) == 0
}

test_validate_kubelet_config_yaml_ownership_no_results {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletConfigYamlConfigurationFileOwnership": {"values": []}},
	}

	count(r) == 0
}

test_validate_kubelet_config_yaml_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletConfigYamlConfigurationFileOwnership": {"values": ["user:user"]}},
	}

	count(r) == 1
}
