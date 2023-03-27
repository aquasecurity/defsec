package builtin.kubernetes.KCV0020

test_audit_log_maxage_is_set_30 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-apiserver",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-apiserver", "--advertise-address=192.168.49.2", "--audit-log-maxage=30"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_audit_log_maxage_is_set_10 {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-apiserver",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-apiserver", "--advertise-address=192.168.49.2", "--audit-log-maxage=30", "--secure-port=10"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_audit_log_maxage_is_not_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-apiserver",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-apiserver", "--advertise-address=192.168.49.2", "--profiling=true", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate"
}
