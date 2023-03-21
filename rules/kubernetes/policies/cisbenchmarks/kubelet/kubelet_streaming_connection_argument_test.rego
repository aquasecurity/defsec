package builtin.kubernetes.KCV0085

test_validate_validate_kubelet_streaming_connection_idle_timeout_set_zero {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletStreamingConnectionIdleTimeoutArgumentSet": {"values": [0]}},
	}

	count(r) == 1
}

test_validate_validate_kubelet_streaming_connection_idle_timeout_set_non_zero {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletStreamingConnectionIdleTimeoutArgumentSet": {"values": [1]}},
	}

	count(r) == 0
}
