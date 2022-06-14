package builtin.kubernetes.KSV046

test_resource_verb_role_secrets {
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
			"verbs": ["delete"],
		}],
	}

	count(r) > 0
}

test_resource_verb_role_pods {
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
			"verbs": ["deletecollection"],
		}],
	}

	count(r) > 0
}

test_resource_verb_role_deployments {
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
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_resource_verb_role_daemonsets {
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
			"verbs": ["list"],
		}],
	}

	count(r) > 0
}

test_resource_verb_role_statefulsets {
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
			"verbs": ["get"],
		}],
	}

	count(r) > 0
}

test_resource_verb_role_replicationcontrollers {
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
			"verbs": ["impersonate"],
		}],
	}

	count(r) > 0
}

test_resource_resource_role_no_specific_verb {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["impersonate"],
			"verbs": ["aaa"],
		}],
	}

	count(r) == 0
}

test_resource_verb_role_no_any_verb {
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
