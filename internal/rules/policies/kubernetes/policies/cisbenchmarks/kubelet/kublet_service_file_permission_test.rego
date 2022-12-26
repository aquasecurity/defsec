package builtin.kubernetes.KCV0069

test_validate_service_file_permission_equal_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"KubeletServiceFilePermissions": [600]},
	}

	count(r) == 0
}

test_validate_service_file_permission_lower_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "worker",
		"info": {"KubeletServiceFilePermissions": [500]},
	}

	count(r) == 0
}

test_validate_service_file_permission_higher_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"KubeletServiceFilePermissions": [700]},
	}

	count(r) == 1
}
