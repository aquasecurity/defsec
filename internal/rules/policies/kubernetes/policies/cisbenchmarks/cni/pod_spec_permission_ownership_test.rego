package builtin.kubernetes.KCV0057

test_validate_spec_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"containerNetworkInterfaceFileOwnership": ["root:root"]},
	}

	count(r) == 0
}

test_validate_spec_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"containerNetworkInterfaceFileOwnership": ["user:user"]},
	}

	count(r) == 1
}
