package builtin.kubernetes.KSV0137

test_service_account_private_key_file_is_not_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-controller-manager",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": "kube-controller-manager --allocate-node-cidrs=true --use-service-account-credentials=true",
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --service-account-private-key-file argument is set as appropriate"
}

test_service_account_private_key_file_is_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-controller-manager",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": "kube-controller-manager --allocate-node-cidrs=true --service-account-private-key-file=<filename>",
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}
