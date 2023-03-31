package builtin.kubernetes.KCV0073

test_validate_kubelet_config_permission_equal_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletConfFilePermissions": {"values": [600]}},
	}

	count(r) == 0
}

test_validate_kublet_config_permission_lower_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletConfFilePermissions": {"values": [500]}},
	}

	count(r) == 0
}

test_validate_kubelet_config_permission_no_result {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletConfFilePermissions": {"values": []}},
	}

	count(r) == 0
}

test_validate_kubelet_config_permission_higher_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletConfFilePermissions": {"values": [700]}},
	}

	count(r) == 1
}
