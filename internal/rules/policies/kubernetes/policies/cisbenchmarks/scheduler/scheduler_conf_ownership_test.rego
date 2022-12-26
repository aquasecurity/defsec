package builtin.kubernetes.KCV0063

test_validate_scheduler_config_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"schedulerConfFileOwnership": ["root:root"]},
	}

	count(r) == 0
}

test_validate_scheduler_config_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"schedulerConfFileOwnership": ["user:user"]},
	}

	count(r) == 1
}
