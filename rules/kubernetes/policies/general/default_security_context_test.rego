package builtin.kubernetes.KSV118

test_container_with_default_security_context {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "pod-with-default-container"},
		"spec": {"containers": [{
			"name": "default-container",
			"image": "busybox",
			"securityContext": {},
		}]},
	}

	# Assert that the result should be denied due to default security context
	count(r) == 1
}

test_container_with_non_default_security_context {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "pod-with-non-default-container"},
		"spec": {"containers": [{
			"name": "non-default-container",
			"image": "busybox",
			"securityContext": {"runAsUser": 1001},
		}]},
	}

	# Assert that the result should be empty because security context is non-default
	count(r) == 0
}
