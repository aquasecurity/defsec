package builtin.kubernetes.KSV0134

test_terminated_pod_gc_threshold_is_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-conrtoller-manager",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": "kube-controller-manager --allocate-node-cidrs=true",
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate"
}

test_terminated_pod_gc_threshold_is_not_set {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-conrtoller-manager",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": "kube-controller-manager --allocate-node-cidrs=true --terminated-pod-gc-threshold=10",
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}
