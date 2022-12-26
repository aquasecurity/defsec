package builtin.kubernetes.KCV0070

test_validate_service_file_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletServiceFileOwnership": ["root:root"]},
	}

	count(r) == 0
}

test_validate_service_file_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletServiceFileOwnership": ["user:user"]},
	}

	count(r) == 1
}
