package builtin.kubernetes.KCV0061

test_validate_admin_config_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"AdminConfFileOwnership": ["root:root"]},
	}

	count(r) == 0
}

test_validate_admin_config_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"AdminConfFileOwnership": ["user:user"]},
	}

	count(r) == 1
}
