package builtin.kubernetes.KCV0068

test_validate_pki_cert_permission_lower_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"KubernetesPKICertificateFilePermissions": [500]},
	}

	count(r) == 0
}

test_validate_pki_cert_permission_bigger_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"KubernetesPKICertificateFilePermissions": [700]},
	}

	count(r) == 1
}
