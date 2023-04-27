package builtin.kubernetes.KCV0082

test_validate_read_only_argument_set_zero {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletReadOnlyPortArgumentSet": {"values": [0]}},
	}

	count(r) == 0
}

test_validate_read_only_argument_set_non_zero {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletReadOnlyPortArgumentSet": {"values": [1]}},
	}

	count(r) == 1
}

test_validate_read_only_argument_not_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletReadOnlyPortArgumentSet": {"values": []}},
	}

	count(r) == 0
}
