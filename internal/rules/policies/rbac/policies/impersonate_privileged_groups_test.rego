package builtin.kubernetes.KSV043

test_impersonate_privileged_groups {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["groups"],
			"verbs": ["impersonate"],
		}],
	}

	count(r) > 0
}

test_impersonate_privileged_groups_not_api_group {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["aaa"],
			"resources": ["groups"],
			"verbs": ["impersonate"],
		}],
	}

	count(r) == 0
}

test_impersonate_privileged_groups_no_resource {
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
			"verbs": ["impersonate"],
		}],
	}

	count(r) == 0
}

test_impersonate_privileged_groups_no_resource_no_verbs {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["groups"],
			"verbs": ["update"],
		}],
	}

	count(r) == 0
}
