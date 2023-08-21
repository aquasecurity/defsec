package builtin.kubernetes.KSV1010

test_configMap_with_sensitive_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ConfigMap",
		"metadata": {"name": "cm-with-sensitive"},
		"data": {
			"color.good": "blue",
			"color.bad": "yellow",
			"username": "test",
		},
	}

	count(r) == 1
	r[_].msg == "ConfigMap 'cm-with-sensitive' in 'default' namespace stores sensitive contents in key(s) or value(s) '{\"username\"}'"
}

test_configMap_with_sensitive_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ConfigMap",
		"metadata": {"name": "cm-with-sensitive"},
		"data": {
			"color.good": "blue",
			"color.bad": "yellow",
		},
	}

	count(r) == 0
}
