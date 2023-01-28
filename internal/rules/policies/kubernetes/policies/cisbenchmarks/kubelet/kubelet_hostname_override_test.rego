package builtin.kubernetes.KCV0086

test_validate_hostname_override_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletHostnameOverrideArgumentSet": {"values": ["name"]}},
	}

	count(r) == 1
}

test_validate_hostname_override_not_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletHostnameOverrideArgumentSet": {"values": []}},
	}

	count(r) == 0
}
