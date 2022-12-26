package builtin.kubernetes.KCV0071

test_validate_kube_config_permission_equal_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeconfigFileExistsPermissions": [600]},
	}

	count(r) == 0
}

test_validate_kube_config_permission_lower_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeconfigFileExistsPermissions": [500]},
	}

	count(r) == 0
}

test_validate_kube_config_permission_no_result {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeconfigFileExistsPermissions": []},
	}

	count(r) == 0
}

test_validate_kube_config_permission_higher_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeconfigFileExistsPermissions": [700]},
	}

	count(r) == 1
}
