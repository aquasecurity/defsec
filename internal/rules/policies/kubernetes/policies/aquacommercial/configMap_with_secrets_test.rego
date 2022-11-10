package builtin.kubernetes.KSV0109

test_configMap_with_secrets_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ConfigMap",
		"metadata": {"name": "cm-with-secrets"},
		"data": {
			"password": "password123",
			"secretkey": "test",
		},
	}

	count(r) == 1
	r[_].msg == "ConfigMap 'cm-with-secrets' in 'default' namespace stores secrets in key(s) or value(s) '{\"password\", \"secretkey\"}'"
}

test_configMap_with_secrets_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ConfigMap",
		"metadata": {"name": "cm-with-secrets"},
		"data": {
			"color.good": "blue",
			"color.bad": "yellow",
		},
	}

	count(r) == 0
}
