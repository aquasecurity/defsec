package builtin.kubernetes.KCV0034

test_profiling_is_set_to_false {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "controller-manager",
			"labels": {
				"component": "kube-controller-manager",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-controller-manager", "--allocate-node-cidrs=true", "--profiling=false"],
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
			"name": "controller-manager",
			"labels": {
				"component": "kube-controller-manager",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-controller-manager", "--allocate-node-cidrs=true", "--profiling=true"],
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
			"name": "controller-manager",
			"labels": {
				"component": "kube-controller-manager",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-controller-manager", "--allocate-node-cidrs=true"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --profiling argument is set to false"
}
