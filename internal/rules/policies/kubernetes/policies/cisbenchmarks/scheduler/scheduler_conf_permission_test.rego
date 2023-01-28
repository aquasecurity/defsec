package builtin.kubernetes.KCV0062

test_validate_scheduler_config_permission_equal_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"schedulerConfFilePermissions": {"values": [600]}},
	}

	count(r) == 0
}

test_validate_scheduler_config_permission_lower_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"schedulerConfFilePermissions": {"values": [500]}},
	}

	count(r) == 0
}

test_validate_scheduler_config_permission_higher_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"schedulerConfFilePermissions": {"values": [700]}},
	}

	count(r) == 1
}
