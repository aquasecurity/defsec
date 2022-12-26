package builtin.kubernetes.KCV0068

test_validate_pki_cert_permission_lower_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubernetesPKICertificateFilePermissions": {"values": [500]}},
	}

	count(r) == 0
}

test_validate_pki_cert_permission_bigger_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubernetesPKICertificateFilePermissions": {"values": [700]}},
	}

	count(r) == 1
}
