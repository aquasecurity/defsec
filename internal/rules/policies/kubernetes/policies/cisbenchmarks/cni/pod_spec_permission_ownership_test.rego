package builtin.kubernetes.KCV0057

test_validate_spec_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"ContainerNetworkInterfaceFileOwnership": ["root:root"]},
	}

	count(r) == 0
}

test_validate_spec_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"ContainerNetworkInterfaceFileOwnership": ["user:user"]},
	}

	count(r) == 1
}
