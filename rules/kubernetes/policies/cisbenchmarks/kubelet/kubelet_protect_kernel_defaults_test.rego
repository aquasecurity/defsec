package builtin.kubernetes.KCV0083

test_validate_kernel_defaults_auth_set_true {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletProtectKernelDefaultsArgumentSet": {"values": ["false"]}},
	}

	count(r) == 1
}

test_validate_kubelet_defaults_auth_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletProtectKernelDefaultsArgumentSet": {"values": []}},
	}

	count(r) == 1
}

test_validate_kubelet_defaults_auth_set_false {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletProtectKernelDefaultsArgumentSet": {"values": ["true"]}},
	}

	count(r) == 0
}
