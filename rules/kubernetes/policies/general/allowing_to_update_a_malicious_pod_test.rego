package builtin.kubernetes.KSV048

test_update_malicious_pod_deployments {
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
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_daemonsets {
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
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_statefulsets {
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
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_replicationcontrollers {
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
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_replicasets {
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
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_cronjobs {
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
			"verbs": ["update"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_not_secret_resource {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["deployments1"],
			"verbs": ["update"],
		}],
	}

	count(r) == 0
}

test_update_malicious_pod_deployment {
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
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_daemonsets {
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
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_statefulsets {
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
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_replicationcontrollers {
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
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_replicasets {
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
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_jobs {
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
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}

test_update_malicious_pod_cronjobs {
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
			"verbs": ["create"],
		}],
	}

	count(r) > 0
}
