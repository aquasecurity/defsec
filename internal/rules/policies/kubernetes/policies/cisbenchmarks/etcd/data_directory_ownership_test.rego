package builtin.kubernetes.KCV0059

test_validate_data_directory_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"EtcdDataDirectoryOwnership": ["etcd:etcd"]},
	}

	count(r) == 0
}

test_validate_data_directory_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Nodeinfo",
		"type": "master",
		"info": {"EtcdDataDirectoryOwnership": ["user:user"]},
	}

	count(r) == 1
}
