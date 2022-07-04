package builtin.kubernetes.KSV0141

test_profiling_is_set_to_false {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "scheduler",
			"labels": {
				"component": "kube-scheduler",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": "kube-scheduler --authentication-kubeconfig=<path/to/file> --profiling=false",
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_profiling_is_set_to_true {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "scheduler",
			"labels": {
				"component": "kube-scheduler",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": "kube-scheduler --authentication-kubeconfig=<path/to/file> --profiling=true",
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --profiling argument is set to false"
}

test_profiling_is_not_configured {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "scheduler",
			"labels": {
				"component": "kube-scheduler",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": "kube-scheduler --authentication-kubeconfig=<path/to/file>",
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --profiling argument is set to false"
}
