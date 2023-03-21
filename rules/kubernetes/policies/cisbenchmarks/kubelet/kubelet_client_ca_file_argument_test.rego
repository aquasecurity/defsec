package builtin.kubernetes.KCV0081

test_validate_kubelet_anonymous_auth_set_true {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletClientCaFileArgumentSet": {"values": [""]}},
	}

	count(r) == 1
}

test_validate_kubelet_anonymous_auth_not_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletClientCaFileArgumentSet": {"values": []}},
	}

	count(r) == 1
}

test_validate_kubelet_anonymous_auth_set_false {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletClientCaFileArgumentSet": {"values": ["/temp/file/ca"]}},
	}

	count(r) == 0
}
