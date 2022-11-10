package builtin.kubernetes.KSV0108

test_service_with_externalip_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Service",
		"metadata": {"name": "service_with_externalip"},
		"spec": {
			"ports": [{
				"name": "http",
				"port": 80,
				"protocol": "TCP",
				"targetPort": 9376,
			}],
			"selector": {"app.kubernetes.io/name": "MyApp"},
			"externalIPs": ["192.168.0.106"],
		},
	}

	count(r) == 1
	r[_].msg == "Service 'service_with_externalip' in 'default' namespace should not set external IPs or external Name"
}

test_service_with_externalip_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Service",
		"metadata": {"name": "service_with_externalip"},
		"spec": {
			"ports": [{
				"name": "http",
				"port": 80,
				"protocol": "TCP",
				"targetPort": 9376,
			}],
			"selector": {"app.kubernetes.io/name": "MyApp"},
		},
	}

	count(r) == 0
}
