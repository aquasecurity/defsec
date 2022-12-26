package builtin.kubernetes.KCV0065

test_validate_controller_manager_config_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"controllerManagerConfFileOwnership": ["root:root"]},
	}

	count(r) == 0
}

test_validate_controller_manager_config_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"controllerManagerConfFileOwnership": ["user:user"]},
	}

	count(r) == 1
}
