package builtin.kubernetes.KSV053

test_getting_shell_on_pods {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/exec"],
			"verbs": ["create"],
		}],
	}

	count(r) == 1
}

test_getting_shell_on_pods_no_pod_exec {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/exec1"],
			"verbs": ["create"],
		}],
	}

	count(r) == 0
}

test_getting_shell_on_pods_no_verb_create {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/exec"],
			"verbs": ["create1"],
		}],
	}

	count(r) == 0
}

test_getting_shell_on_pods_no_resource_pod {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/exec"],
			"verbs": ["create1"],
		}],
	}

	count(r) == 0
}

test_getting_shell_on_pods_no_verb_get {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [{
			"apiGroups": ["*"],
			"resources": ["pods/exec"],
			"verbs": ["create1"],
		}],
	}

	count(r) == 0
}
