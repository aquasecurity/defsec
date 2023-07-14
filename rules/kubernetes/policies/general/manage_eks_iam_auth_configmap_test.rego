package builtin.kubernetes.KSV115

test_manageEKSIAMAuthConfigmap_verb_create {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_update {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_patch {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_delete {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_deletecollection {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_impersonate {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_all {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) > 0
}

test_manageEKSIAMAuthConfigmap_verb_wrong {
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
			"resourceNames": ["aws-auth"],
		}],
	}

	count(r) == 0
}
