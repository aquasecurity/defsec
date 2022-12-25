package builtin.kubernetes.KCV0048

test_validate_spec_permission_equal_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"kubeAPIServerSpecFilePermission": [600]},
	}

	count(r) == 0
}

test_validate_spec_permission_lower_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"kubeAPIServerSpecFilePermission": [500]},
	}

	count(r) == 0
}

test_validate_spec_permission_higher_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"kubeAPIServerSpecFilePermission": [700]},
	}

	count(r) == 1
}