package builtin.kubernetes.KCV0070

test_validate_service_file_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"KubeletServiceFileOwnership": ["root:root"]},
	}

	count(r) == 0
}

test_validate_service_file_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "worker",
		"info": {"KubeletServiceFileOwnership": ["user:user"]},
	}

	count(r) == 1
}
