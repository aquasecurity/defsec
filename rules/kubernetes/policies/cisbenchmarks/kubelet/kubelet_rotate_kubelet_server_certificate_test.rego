package builtin.kubernetes.KCV0091

test_validate_rotate_kubelet_server_certificate_true {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletRotateKubeletServerCertificateArgumentSet": {"values": ["true"]}},
	}

	count(r) == 0
}

test_validate_rotate_kubelet_server_certificate_false {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletRotateKubeletServerCertificateArgumentSet": {"values": ["false"]}},
	}

	count(r) == 1
}

test_validate_rotate_kubelet_server_certificate_empty {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletRotateKubeletServerCertificateArgumentSet": {"values": []}},
	}

	count(r) == 1
}
