package builtin.kubernetes.KSV117

test_container_with_privileged_port {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "pod-with-privileged-container"},
		"spec": {
			"containers": [
				{
					"name": "privileged-container",
					"image": "nginx",
					"ports": [{"containerPort": 80}]
				}
			]
		}
	}

	# Assert that the result should NOT be empty due to privileged port (80)
	count(r) == 1
}

test_container_with_non_privileged_port {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "pod-with-non-privileged-container"},
		"spec": {
			"containers": [
				{
					"name": "non-privileged-container",
					"image": "nginx",
					"ports": [{"containerPort": 8080}]
				}
			]
		}
	}

	# Assert that the result should be empty due to non-privileged port (8080)
	count(r) == 0
}

