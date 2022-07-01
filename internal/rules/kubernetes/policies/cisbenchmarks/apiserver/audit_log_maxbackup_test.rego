package builtin.kubernetes.KCV0021

test_audit_log_maxbackup_is_set_30 {
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
			"command": ["kube-apiserver", "--advertise-address=192.168.49.2", "--audit-log-maxbackup=30"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_audit_log_maxbackup_is_set_10 {
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
			"command": ["kube-apiserver", "--advertise-address=192.168.49.2", "--audit-log-maxbackup=30", "--secure-port=10"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_audit_log_maxbackup_is_not_set {
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
	r[_].msg == "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate"
}
