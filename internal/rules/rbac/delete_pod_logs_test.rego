package builtin.kubernetes.KSV042

test_delete_podsLog_restricted_verb_delete {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/log"],
			"verbs": ["delete"],
		}],
	}

	count(r) > 0
}

test_delete_podsLog_restricted_verb_delete_collection {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/log"],
			"verbs": ["deletecollection"],
		}],
	}

	count(r) > 0
}

test_delete_podsLog_restricted_verb_all {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/log"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_delete_podsLog_restricted_verb_other {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/log"],
			"verbs": ["just"],
		}],
	}

	count(r) == 0
}
