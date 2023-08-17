package builtin.kubernetes.KSV119

# Test case for a Pod with a container including NET_RAW capability
test_pod_with_container_net_raw_capability {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "net-raw-pod"},
		"spec": {"containers": [
			{
				"name": "container-a",
				"image": "nginx",
				"securityContext": {"capabilities": {"add": ["NET_RAW", "SYS_ADMIN"]}},
			},
			{
				"name": "container-b",
				"image": "busybox",
				"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}},
			},
		]},
	}

	# Assert that the result should be denied due to NET_RAW capability
	count(r) == 1
}

# Test case for a Pod with no container including NET_RAW capability
test_pod_without_container_net_raw_capability {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "no-net-raw-pod"},
		"spec": {"containers": [
			{
				"name": "container-x",
				"image": "nginx",
				"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}},
			},
			{
				"name": "container-y",
				"image": "busybox",
				"securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}},
			},
		]},
	}

	# Assert that the result should be allowed (no denial)
	count(r) == 0
}
