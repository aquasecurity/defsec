package builtin.kubernetes.KSV114

test_manageWebhookConfig_verb_create {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["mutatingwebhookconfigurations"],
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_manageWebhookConfig_verb_update {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["mutatingwebhookconfigurations"],
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_manageWebhookConfig_verb_patch {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["mutatingwebhookconfigurations"],
			"verbs": ["patch"],
		}],
	}

	count(r) > 0
}

test_manageWebhookConfig_verb_delete {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["validatingwebhookconfigurations"],
			"verbs": ["delete"],
		}],
	}

	count(r) > 0
}

test_manageWebhookConfig_verb_deletecollection {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["validatingwebhookconfigurations"],
			"verbs": ["deletecollection"],
		}],
	}

	count(r) > 0
}

test_manageWebhookConfig_verb_impersonate {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["validatingwebhookconfigurations"],
			"verbs": ["impersonate"],
		}],
	}

	count(r) > 0
}

test_validatingWebhook_manageWebhookConfig_verb_all {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["validatingwebhookconfigurations"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_mutatingWebhook_manageWebhookConfig_verb_all {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["mutatingwebhookconfigurations"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_manageWebhookConfig_verb_wrong {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRole",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["mutatingwebhookconfigurations"],
			"verbs": ["just"],
		}],
	}

	count(r) == 0
}
