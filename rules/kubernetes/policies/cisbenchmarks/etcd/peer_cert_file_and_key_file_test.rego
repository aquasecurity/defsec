package builtin.kubernetes.KCV0045

test_only_etcd_peer_cert_file_is_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["etcd", "--advertise-client-urls=https://192.168.49.2:2379", "--peer-cert-file=<filename>"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate"
}

test_only_etcd_peer_key_file_is_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["etcd", "--advertise-client-urls=https://192.168.49.2:2379", "--peer-key-file=<filename>"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate"
}

test_etcd_peer_cert_file_and_peer_key_file_are_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["etcd", "--peer-cert-file=<filename>", "--peer-key-file=<filename>"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_etcd_peer_cert_file_and_peer_key_file_are_not_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["etcd", "--advertise-client-urls=https://192.168.49.2:2379"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate"
}
