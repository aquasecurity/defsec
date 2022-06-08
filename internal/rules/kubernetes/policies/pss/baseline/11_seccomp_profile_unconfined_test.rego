package builtin.kubernetes.KSV104

test_base_securityContext_seccompProfile_unconfined_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {
			"securityContext": {"seccompProfile": {"type": "Unconfined"}},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 1
	r[_].msg == "You should not set Seccomp profile to 'Unconfined'."
}

test_base_securityContext_seccompProfile_unspecified_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {
			"securityContext": {"seccompProfile": {}},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 0
}

test_base_securityContext_seccompProfile_RuntimeDefault_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {
			"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 0
}

test_container_securityContext_seccompProfile_unconfined_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"seccompProfile": {"type": "Unconfined"}},
		}]},
	}

	count(r) == 1
	r[_].msg == "You should not set Seccomp profile to 'Unconfined'."
}

test_container_securityContext_seccompProfile_unspecified_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"seccompProfile": {}},
		}]},
	}

	count(r) == 0
}

test_container_securityContext_seccompProfile_RuntimeDefault_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
		}]},
	}

	count(r) == 0
}
