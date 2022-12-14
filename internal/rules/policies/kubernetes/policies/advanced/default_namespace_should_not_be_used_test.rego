package builtin.kubernetes.KSV110

test_pod_with_default_namespace {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"creationTimestamp": "2022-01-12T10:28:20Z",
			"labels": {
				"app": "redis",
				"role": "master",
				"tier": "backend",
			},
			"name": "redis-master-85547b7b9-fxnrp",
			"namespace": "default",
			"resourceVersion": "443282",
		},
		"spec": {"containers": [{
			"image": "redis",
			"imagePullPolicy": "Always",
			"name": "master",
			"terminationMessagePath": "/dev/termination-log",
			"terminationMessagePolicy": "File",
			"volumeMounts": [{
				"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
				"name": "kube-api-access-85g42",
				"readOnly": true,
			}],
		}]},
	}

	count(r) == 1
}

test_pod_non_default_namespace {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"creationTimestamp": "2022-01-12T10:28:20Z",
			"labels": {
				"component": "kube-apiserver",
				"app": "redis",
				"role": "master",
				"tier": "control-plane",
			},
			"name": "redis-master-85547b7b9-fxnrp",
			"namespace": "my-system",
			"resourceVersion": "443282",
		},
		"spec": {
			"containers": [{
				"image": "redis",
				"imagePullPolicy": "Always",
				"name": "master",
				"terminationMessagePath": "/dev/termination-log",
				"terminationMessagePolicy": "File",
				"volumeMounts": [{
					"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
					"name": "kube-api-access-85g42",
					"readOnly": true,
				}],
			}],
			"priorityClassName": "system-node-critical",
		},
	}

	count(r) == 0
}
