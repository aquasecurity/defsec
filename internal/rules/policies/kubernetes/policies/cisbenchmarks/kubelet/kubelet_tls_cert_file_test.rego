package builtin.kubernetes.KCV0088

test_validate_tls_cert_file_empty {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletTlsCertFileTlsArgumentSet": {"values": []}},
	}

	count(r) == 1
}

test_validate_tls_cert_file_real {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletTlsCertFileTlsArgumentSet": {"values": ["a.crt"]}},
	}

	count(r) == 0
}

test_validate_tls_cert_file_fake {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletTlsCertFileTlsArgumentSet": {"values": ["a.txt"]}},
	}

	count(r) == 1
}
