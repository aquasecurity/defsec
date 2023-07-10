package builtin.kubernetes.KSV104

test_container_seccomp_profile_unconfined_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {"containers": [{
			"name": "hello",
			"image": "busybox",
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
		}]},
	}

	count(r) == 0
}

test_container_seccomp_profile_unconfined_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "my-pod"},
		"spec": {"containers": [
			{
				"name": "container-1",
				"image": "nginx",
				"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
			},
			{
				"name": "container-2",
				"image": "busybox",
				"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
			},
		]},
	}

	count(r) == 0
}
