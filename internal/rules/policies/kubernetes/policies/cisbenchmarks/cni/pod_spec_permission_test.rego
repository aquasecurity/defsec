package builtin.kubernetes.KCV0056

test_validate_spec_permission_equal_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"containerNetworkInterfaceFilePermissions": {"values": [600, 600]}},
	}

	count(r) == 0
}

test_validate_spec_permission_lower_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"containerNetworkInterfaceFilePermissions": {"values": [500, 600]}},
	}

	count(r) == 0
}

test_validate_spec_permission_higher_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"containerNetworkInterfaceFilePermissions": {"values": [700, 755]}},
	}

	count(r) == 1
}
