package builtin.kubernetes.KSV121

# Test case for a Pod with no disallowed volumes
test_pod_with_allowed_volumes {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "allowed-pod"},
		"spec": {
			"containers": [{
				"command": ["sh", "-c", "echo 'Hello' && sleep 1h"],
				"image": "busybox",
				"name": "hello",
			}],
			"volumes": [{
				"name": "volume-b",
				"hostPath": {"path": "/data"}, # An allowed volume
			}],
		},
	}

	# Assert that the result should be allowed (no denial)
	count(r) == 0
}

# Test case for multiple containers in a Pod, some with disallowed volumes
test_pod_with_disallowed_volumes_multiple_containers {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "multi-container-pod"},
		"spec": {
			"containers": [
				{
					"command": ["sh", "-c", "echo 'Hello' && sleep 1h"],
					"image": "busybox",
					"name": "container-a",
				},
				{
					"command": ["sh", "-c", "echo 'World' && sleep 1h"],
					"image": "nginx",
					"name": "container-b",
				},
			],
			"volumes": [
				{
					"name": "volume-c",
					"hostPath": {"path": "/etc"}, # A disallowed volume
				},
				{
					"name": "volume-d",
					"hostPath": {"path": "/data"}, # An allowed volume
				},
			],
		},
	}

	# Assert that the result should be denied due to the disallowed volume
	count(r) == 1
}

# Test case for a Pod without any volumes
test_pod_without_volumes {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "no-volume-pod"},
		"spec": {"containers": [{
			"command": ["sh", "-c", "echo 'Hello' && sleep 1h"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	# Assert that the result should be allowed (no denial)
	count(r) == 0
}
