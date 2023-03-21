package builtin.kubernetes.KCV0076

test_validate_certificate_authorities_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"certificateAuthoritiesFileOwnership": {"values": ["root:root"]}},
	}

	count(r) == 0
}

test_validate_certificate_authorities_ownership_no_results {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"certificateAuthoritiesFileOwnership": {"values": []}},
	}

	count(r) == 0
}

test_validate_certificate_authorities_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"certificateAuthoritiesFileOwnership": {"values": ["user:user"]}},
	}

	count(r) == 1
}
