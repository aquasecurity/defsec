package builtin.kubernetes.KSV045

test_any_verb_role_secrets {
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
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_pods {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_deployments {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["deployments"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_daemonsets {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["daemonsets"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_statefulsets {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["statefulsets"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_replicationcontrollers {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["replicationcontrollers"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_replicasets {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["replicasets"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_cronjobs {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["cronjobs"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_jobs {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["jobs"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_clusterroles {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["clusterroles"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_roles {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["roles"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_rolebindings {
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
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_clusterrolebindings {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["clusterrolebindings"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_users {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["users"],
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_groups {
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
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_groups {
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
			"verbs": ["*"],
		}],
	}

	count(r) > 0
}

test_any_verb_role_no_specific_resource {
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

test_any_verb_role_no_any_verb {
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
			"verbs": ["aaa"],
		}],
	}

	count(r) == 0
}
