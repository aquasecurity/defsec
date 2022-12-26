package builtin.kubernetes.KCV0067

test_validate_pki_key_permission_lower_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubePKIKeyFilePermissions": [500]},
	}

	count(r) == 0
}

test_validate_pki_key_permission_bigger_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubePKIKeyFilePermissions": [700]},
	}

	count(r) == 1
}
