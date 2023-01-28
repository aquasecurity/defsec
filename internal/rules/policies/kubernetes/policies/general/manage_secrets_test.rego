package builtin.kubernetes.KSV041

test_manage_secrets {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["get"],
		}],
	}

	count(r) > 0
}

test_manage_verb_update {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_manage_verb_list {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["list"],
		}],
	}

	count(r) > 0
}

test_manage_not_secret_resource {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets1"],
			"verbs": ["list"],
		}],
	}

	count(r) == 0
}

test_manage_secret_verb_update {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_manage_secret_verb_impersonate {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["impersonate"],
		}],
	}

	count(r) > 0
}

test_manage_secret_verb_deletecollection {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["deletecollection"],
		}],
	}

	count(r) > 0
}

test_manage_secret_verb_patch {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["patch"],
		}],
	}

	count(r) > 0
}

test_manage_secret_verb_watch {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["secrets"],
			"verbs": ["watch"],
		}],
	}

	count(r) > 0
}
