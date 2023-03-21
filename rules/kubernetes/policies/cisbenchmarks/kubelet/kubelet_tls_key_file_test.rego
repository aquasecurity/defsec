package builtin.kubernetes.KCV0089

test_validate_tls_key_file_empty {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletTlsPrivateKeyFileArgumentSet": {"values": []}},
	}

	count(r) == 1
}

test_validate_tls_key_file_real {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletTlsPrivateKeyFileArgumentSet": {"values": ["a.key"]}},
	}

	count(r) == 0
}

test_validate_tls_key_file_fake {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletTlsPrivateKeyFileArgumentSet": {"values": ["a.txt"]}},
	}

	count(r) == 1
}
