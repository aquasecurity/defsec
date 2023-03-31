package builtin.kubernetes.KCV0059

test_validate_data_directory_ownership_equal_root_root {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"etcdDataDirectoryOwnership": {"values": ["etcd:etcd"]}},
	}

	count(r) == 0
}

test_validate_data_directory_ownership_equal_user {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"etcdDataDirectoryOwnership": {"values": ["user:user"]}},
	}

	count(r) == 1
}
