package builtin.kubernetes.KSV047

test_privilege_escalation_from_node_proxy_create {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["nodes/proxy"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_privilege_escalation_from_node_proxy_get {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["nodes/proxy"],
			"verbs": ["get"],
		}],
	}

	count(r) > 0
}

test_privilege_escalation_from_node_proxy_not_secret_resource {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["nodes/proxy1"],
			"verbs": ["create"],
		}],
	}

	count(r) == 0
}

test_privilege_escalation_from_node_proxy_not_secret_resource {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["nodes/proxy"],
			"verbs": ["update"],
		}],
	}

	count(r) == 0
}
