package builtin.kubernetes.KCV0090

test_validate_rotate_certificates_true {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletRotateCertificatesArgumentSet": {"values": ["true"]}},
	}

	count(r) == 0
}

test_validate_rotate_certificates_false {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletRotateCertificatesArgumentSet": {"values": ["false"]}},
	}

	count(r) == 1
}

test_validate_rotate_certificates_empty {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletRotateCertificatesArgumentSet": {"values": []}},
	}

	count(r) == 1
}
