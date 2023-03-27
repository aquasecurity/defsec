package builtin.kubernetes.KCV0079

test_validate_kubelet_anonymous_auth_set_true {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletAnonymousAuthArgumentSet": {"values": ["true"]}},
	}

	count(r) == 1
}

test_validate_kubelet_anonymous_auth_not_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletAnonymousAuthArgumentSet": {"values": []}},
	}

	count(r) == 1
}

test_validate_kubelet_anonymous_auth_set_false {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletAnonymousAuthArgumentSet": {"values": ["false"]}},
	}

	count(r) == 0
}
