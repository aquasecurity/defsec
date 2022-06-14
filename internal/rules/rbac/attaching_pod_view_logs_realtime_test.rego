package builtin.kubernetes.KSV054

test_getting_shell_on_pods {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["*"],
				"resources": ["pods/attach"],
				"verbs": ["create"],
			},
			{
				"apiGroups": ["*"],
				"resources": ["pods"],
				"verbs": ["get"],
			},
		],
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
		"rules": [
			{
				"apiGroups": ["*"],
				"resources": ["pods/attach1"],
				"verbs": ["create"],
			},
			{
				"apiGroups": ["*"],
				"resources": ["pods"],
				"verbs": ["get"],
			},
		],
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
		"rules": [
			{
				"apiGroups": ["*"],
				"resources": ["pods/attach"],
				"verbs": ["create1"],
			},
			{
				"apiGroups": ["*"],
				"resources": ["pods"],
				"verbs": ["get"],
			},
		],
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
		"rules": [
			{
				"apiGroups": ["*"],
				"resources": ["pods/attach"],
				"verbs": ["create1"],
			},
			{
				"apiGroups": ["*"],
				"resources": ["pods1"],
				"verbs": ["get"],
			},
		],
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
		"rules": [
			{
				"apiGroups": ["*"],
				"resources": ["pods/attach"],
				"verbs": ["create1"],
			},
			{
				"apiGroups": ["*"],
				"resources": ["pods"],
				"verbs": ["get1"],
			},
		],
	}

	count(r) == 0
}
