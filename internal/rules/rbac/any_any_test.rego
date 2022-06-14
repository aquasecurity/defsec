package builtin.kubernetes.KSV044

test_any_any_role {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["*"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_any_role_not_api_group {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["aaa"],
			"resources": ["*"],
			"verbs": ["*"],
		}],
	}

	count(r) == 0
}

test_any_any_role_no_resource {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["aaa"],
			"verbs": ["*"],
		}],
	}

	count(r) == 0
}

test_any_any_role_no_resource_no_verbs {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["*"],
			"verbs": ["update"],
		}],
	}

	count(r) == 0
}
