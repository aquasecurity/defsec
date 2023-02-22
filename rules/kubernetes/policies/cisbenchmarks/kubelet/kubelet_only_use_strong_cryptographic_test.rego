package builtin.kubernetes.KCV0092

test_validate_do_not_use_strong_cryptographic {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletOnlyUseStrongCryptographic": {"values": ["aaa"]}},
	}

	count(r) == 1
}

test_validate_do_use_strong_cryptographic {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletOnlyUseStrongCryptographic": {"values": ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]}},
	}

	count(r) == 0
}

test_validate_do_use_strong_cryptographic_empty {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletOnlyUseStrongCryptographic": {"values": []}},
	}

	count(r) == 1
}
