package builtin.kubernetes.KCV0067

test_validate_pki_key_permission_lower_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"KubePKIKeyFilePermissions": [500]},
	}

	count(r) == 0
}

test_validate_pki_key_permission_bigger_600 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"KubePKIKeyFilePermissions": [700]},
	}

	count(r) == 1
}
