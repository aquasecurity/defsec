package builtin.kubernetes.KCV0013

test_pod_security_policy_is_set {
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
			"command": ["kube-apiserver", "--enable-admission-plugins=AlwaysPullImages,PodSecurityPolicy"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_pod_security_policy_is_not_set {
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
			"command": ["kube-apiserver", "--enable-admission-plugins=AlwaysPullImages"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used"
}

test_pod_security_policy_is_not_set_and_seurity_context_deny_is_set {
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
			"command": ["kube-apiserver", "--enable-admission-plugins=AlwaysPullImages,SecurityContextDeny"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_both_pod_security_policy_and_seurity_context_deny_are_set {
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
			"command": ["kube-apiserver", "--enable-admission-plugins=AlwaysPullImages,PodSecrutiyPolicy,SecurityContextDeny"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}
