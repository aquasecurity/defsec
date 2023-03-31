package builtin.kubernetes.KCV0080

test_validate_kubelet_authorization_mode_set_alwaysAllow {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletAuthorizationModeArgumentSet": {"values": ["AlwaysAllow"]}},
	}

	count(r) == 1
}

test_validate_kubelet_authorization_mode_not_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletAuthorizationModeArgumentSet": {"values": []}},
	}

	count(r) == 1
}

test_validate_kubelet_authorization_mode_set_alwaysAllow {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletAuthorizationModeArgumentSet": {"values": ["RBAC"]}},
	}

	count(r) == 0
}
