package builtin.kubernetes.KSV049

test_manageConfigmaps_verb_create {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_update {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_patch {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["patch"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_delete {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["delete"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_deletecollection {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["deletecollection"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_impersonate {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["impersonate"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_all {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_manageConfigmaps_verb_wrong {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["configmaps"],
			"verbs": ["just"],
		}],
	}

	count(r) == 0
}
