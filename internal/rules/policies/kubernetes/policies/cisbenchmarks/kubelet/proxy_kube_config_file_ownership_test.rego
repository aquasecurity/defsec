package builtin.kubernetes.KCV0072

test_validate_kube_config_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeconfigFileExistsOwnership": ["root:root"]},
	}

	count(r) == 0
}

test_validate_kube_config_ownership_no_results {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeconfigFileExistsOwnership": []},
	}

	count(r) == 0
}

test_validate_kube_config_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeconfigFileExistsOwnership": ["user:user"]},
	}

	count(r) == 1
}
