package builtin.kubernetes.KSV055

test_allowing_users_rolebinding_add_other_users_their_rolebindings {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["rolebindings"],
			"verbs": ["get", "patch"],
		}],
	}

	count(r) > 0
}

test_allowing_users_rolebinding_add_other_users_their_rolebindings_no_resource_rolebinding {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["rolebindings1"],
			"verbs": ["get", "patch"],
		}],
	}

	count(r) == 0
}

test_allowing_users_rolebinding_add_other_users_their_rolebindings_no_verb_get {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["rolebindings"],
			"verbs": ["get1", "patch"],
		}],
	}

	count(r) == 0
}

test_allowing_users_rolebinding_add_other_users_their_rolebindings_no_verb_patch {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["rolebindings"],
			"verbs": ["get", "patch1"],
		}],
	}

	count(r) == 0
}
