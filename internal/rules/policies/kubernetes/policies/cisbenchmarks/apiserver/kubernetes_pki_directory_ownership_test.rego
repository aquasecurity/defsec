package builtin.kubernetes.KCV0066

test_validate_pki_directory_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"KubePKIDirectoryFileOwnership": ["root:root"]},
	}

	count(r) == 0
}

test_validate_pki_directory_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"KubePKIDirectoryFileOwnership": ["user:user"]},
	}

	count(r) == 1
}
